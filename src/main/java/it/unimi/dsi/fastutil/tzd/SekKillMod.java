// Architect: tzdwindows 7
package it.unimi.dsi.fastutil.tzd;

import com.mojang.blaze3d.systems.RenderSystem;
import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.context.CommandContext;
import it.unimi.dsi.fastutil.tzd.bridge.NativeBridge;
import it.unimi.dsi.fastutil.tzd.bridge.UnsafeGateway;
import it.unimi.dsi.fastutil.tzd.gui.GuiHookTargets;
import it.unimi.dsi.fastutil.tzd.protect.PhantomProtector;
import it.unimi.dsi.fastutil.tzd.seckill.EventBusHijacker;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;
import net.minecraft.network.chat.Component;
import net.minecraft.world.entity.LivingEntity;
import net.minecraft.world.food.FoodData;
import net.minecraft.world.item.Item;
import net.minecraftforge.client.event.RenderGuiEvent;
import net.minecraftforge.common.MinecraftForge;
import net.minecraftforge.event.RegisterCommandsEvent;
import net.minecraftforge.eventbus.api.EventPriority;
import net.minecraftforge.eventbus.api.IEventBus;
import net.minecraftforge.fml.common.Mod;
import net.minecraftforge.fml.event.lifecycle.FMLCommonSetupEvent;
import net.minecraftforge.fml.javafmlmod.FMLJavaModLoadingContext;
import net.minecraftforge.registries.DeferredRegister;
import net.minecraftforge.registries.ForgeRegistries;
import net.minecraftforge.registries.RegistryObject;

import java.lang.reflect.Method;

@Mod("tzd_seckill")
public final class SekKillMod {
    public static final String MODID = "tzd_seckill";
    public static final DeferredRegister<Item> ITEMS =
            DeferredRegister.create(ForgeRegistries.ITEMS, MODID);
    public static final RegistryObject<Item> CELESTIAL_REAVER =
            ITEMS.register("celestial_reaver", () -> new Item(new Item.Properties()));

    private static volatile boolean isHooked = false;

    // Native Method* pointers (resolved at setup)
    private static long getHealthSrcPtr = 0L;
    private static long getFoodLevelSrcPtr = 0L;
    private static long getSaturationLevelSrcPtr = 0L;

    static {
        System.err.println("[TZD-SecKill] Mod container loaded (phantom layer active=" + PhantomProtector.isActive() + ")");
    }

    public SekKillMod(FMLJavaModLoadingContext ctx) {
        IEventBus modBus = ctx.getModEventBus();
        ITEMS.register(modBus);

        modBus.addListener(this::onCommonSetup);

        // 注册事件监听器 (LivingHurt / LivingDamage — 攻击放大, 防御归零)
        //MinecraftForge.EVENT_BUS.addListener(EventPriority.HIGHEST, false, EventBusHijacker::onLivingHurt);
        //MinecraftForge.EVENT_BUS.addListener(EventPriority.HIGHEST, false, EventBusHijacker::onLivingDamage);
        //MinecraftForge.EVENT_BUS.register(EventBusHijacker.class);

        // 注册控制台/游戏内指令监听器
        MinecraftForge.EVENT_BUS.addListener(this::onRegisterCommands);

        // ★ 死亡 GUI 每帧渲染: RenderGuiEvent.Post 在 Gui.render 之后每帧触发。
        //  这是安全的: 崩溃根源是 constMethod-swap (已废弃), 不是事件本身。
        //  新的 dispatchHookFreturn0 / interpHookFreturn0 使用原子 64 位写入,
        //  不破坏 VM 一致性, 彻底解决多线程问题。
        MinecraftForge.EVENT_BUS.addListener((RenderGuiEvent.Post event) -> {
            if (GuiHookTargets.isForceRenderActive) {
                GuiHookTargets.onGuiRenderPost(event.getGuiGraphics(), event.getPartialTick());
            }
        });
    }

    private void onCommonSetup(FMLCommonSetupEvent event) {
        event.enqueueWork(() -> {
            try {
                PhantomProtector.activate();
                EventBusHijacker.install();

                UnsafeGateway.bootstrap();
                UnsafeGateway.verifyLoadChain();

                // 1. 加载 Native 动态库
                System.load("F:/秒杀/aitest/seckill_mod/native/seckill_native.dll");

                // 2. 初始化 Native Bridge 偏移与解释器 Hook 机制
                NativeBridge.methodDetectOffsets0();
                NativeBridge.interpHookInit0();
                NativeBridge.dispatchHookInit0();   // TRUE interpreter dispatch table hook

                // 3. 预加载 Targets 类保证符号链接完成
                Class.forName(Targets.class.getName());

                // 4. 解析与提取 LivingEntity.getHealth() 指针
                Method srcGetHealth = findMethod(LivingEntity.class, "m_21223_", "getHealth");
                getHealthSrcPtr = (srcGetHealth != null) ? NativeBridge.methodPtrOf0(srcGetHealth) : 0L;

                // 5. 解析与提取 FoodData.getFoodLevel()
                Method srcGetFoodLevel = findMethod(FoodData.class, "m_38702_", "getFoodLevel");
                getFoodLevelSrcPtr = (srcGetFoodLevel != null) ? NativeBridge.methodPtrOf0(srcGetFoodLevel) : 0L;

                // 6. 解析与提取 FoodData.getSaturationLevel()
                Method srcGetSaturationLevel = findMethod(FoodData.class, "m_38722_", "getSaturationLevel");
                getSaturationLevelSrcPtr = (srcGetSaturationLevel != null) ? NativeBridge.methodPtrOf0(srcGetSaturationLevel) : 0L;

                // 7. 预触发解析, 防止后续首次调用时抛出 NoSuchMethodError
                if (srcGetHealth != null) {
                    try { srcGetHealth.invoke(null); } catch (Throwable ignored) {}
                }

                // 8. 保护 Targets 类 (隐藏 + 移出 JVMTI 列表 + 内存锁)
                NativeBridge.protectClass0(Targets.class);

                System.err.println(String.format(
                        "[TZD-SecKill] Native layer initialized. Ptrs -> Health: 0x%X, Food: 0x%X, Saturation: 0x%X",
                        getHealthSrcPtr, getFoodLevelSrcPtr, getSaturationLevelSrcPtr
                ));
            } catch (Throwable t) {
                System.err.println("[TZD-SecKill] Native setup error: " + t);
            }
        });
    }

    /**
     * 带有环境回退机制的方法查找工具
     */
    private static Method findMethod(Class<?> clazz, String srgName, String deobfName, Class<?>... parameterTypes) {
        try {
            Method m = clazz.getMethod(srgName, parameterTypes);
            m.setAccessible(true);
            return m;
        } catch (NoSuchMethodException ignored) {}
        try {
            Method m = clazz.getMethod(deobfName, parameterTypes);
            m.setAccessible(true);
            return m;
        } catch (NoSuchMethodException ignored) {}
        System.err.println(String.format("[TZD-SecKill] Failed to locate method on %s: '%s' / '%s'.",
                clazz.getName(), srgName, deobfName));
        return null;
    }

    /**
     * 注册 Forge 游戏内指令：/seckill
     */
    private void onRegisterCommands(RegisterCommandsEvent event) {
        CommandDispatcher<CommandSourceStack> dispatcher = event.getDispatcher();
        dispatcher.register(
                Commands.literal("seckill")
                        .requires(source -> source.hasPermission(0))
                        .executes(this::executeToggleSecKill)
        );
    }

    /**
     * 指令响应逻辑：安装或卸载 Hook
     *
     * ★ 彻底修复方案 (no constMethod swap, no JIT crash):
     *   1. dispatchHookFreturn0 — TRUE interpreter dispatch table hook
     *      (patches _active_table[ftos/itos][freturn/ireturn] with a stub
     *       that reads Method* from rbp-24 and overrides the return value
     *       to 0 for hooked methods; non-matching methods pass through)
     *   2. interpHookFreturn0 — fallback: entry-point stub replacement
     *      (allocates a tiny executable stub that returns the captured
     *       constant; redirects _from_interpreted_entry / _from_compiled_entry)
     *   3. Death GUI rendering via RenderGuiEvent.Post (safe: no metadata
     *      corruption, runs on Render thread)
     */
    private int executeToggleSecKill(CommandContext<CommandSourceStack> context) {
        CommandSourceStack source = context.getSource();

        try {
            if (!isHooked) {
                isHooked = true;

                Method tgtGetHealth = Targets.class.getMethod("getHealth");
                Method tgtGetFoodLevel = Targets.class.getMethod("getFoodLevel");
                Method tgtGetSaturation = Targets.class.getMethod("getSaturationLevel");

                boolean hOk = false, fOk = false, sOk = false;

                // ★ 1. 优先使用 dispatchHookFreturn0 (TRUE interpreter dispatch table hook)
                if (getHealthSrcPtr != 0L) {
                    hOk = NativeBridge.dispatchHookFreturn0(getHealthSrcPtr, tgtGetHealth);
                    if (!hOk) hOk = NativeBridge.interpHookFreturn0(getHealthSrcPtr, tgtGetHealth);
                }
                if (getFoodLevelSrcPtr != 0L) {
                    fOk = NativeBridge.dispatchHookFreturn0(getFoodLevelSrcPtr, tgtGetFoodLevel);
                    if (!fOk) fOk = NativeBridge.interpHookFreturn0(getFoodLevelSrcPtr, tgtGetFoodLevel);
                }
                if (getSaturationLevelSrcPtr != 0L) {
                    sOk = NativeBridge.dispatchHookFreturn0(getSaturationLevelSrcPtr, tgtGetSaturation);
                    if (!sOk) sOk = NativeBridge.interpHookFreturn0(getSaturationLevelSrcPtr, tgtGetSaturation);
                }

                // ★ 2. 激活死亡 GUI 渲染
                RenderSystem.recordRenderCall(GuiHookTargets::initForceRender);

                boolean allOk = (getHealthSrcPtr == 0L || hOk)
                        && (getFoodLevelSrcPtr == 0L || fOk)
                        && (getSaturationLevelSrcPtr == 0L || sOk);

                if (allOk) {
                    source.sendSuccess(() -> Component.literal("§a[TZD-SecKill] 你已被抹除"), true);
                } else {
                    source.sendFailure(Component.literal("§c[TZD-SecKill] 部分 Hook 部署失败! "
                            + (hOk ? "H✓" : "H✗") + " " + (fOk ? "F✓" : "F✗") + " "
                            + (sOk ? "S✓" : "S✗")));
                }
            } else {
                isHooked = false;

                // 还原所有 Hook (dispatch table + entry-point stub)
                if (getHealthSrcPtr != 0L) {
                    NativeBridge.dispatchHookFreturnRemove0(getHealthSrcPtr);
                    NativeBridge.interpHookFreturnRemove0(getHealthSrcPtr);
                }
                if (getFoodLevelSrcPtr != 0L) {
                    NativeBridge.dispatchHookFreturnRemove0(getFoodLevelSrcPtr);
                    NativeBridge.interpHookFreturnRemove0(getFoodLevelSrcPtr);
                }
                if (getSaturationLevelSrcPtr != 0L) {
                    NativeBridge.dispatchHookFreturnRemove0(getSaturationLevelSrcPtr);
                    NativeBridge.interpHookFreturnRemove0(getSaturationLevelSrcPtr);
                }

                RenderSystem.recordRenderCall(GuiHookTargets::stopForceRender);
                source.sendSuccess(() -> Component.literal("§e[TZD-SecKill] 秒杀与饱食度 Hook 已成功还原！"), true);
            }
        } catch (Throwable t) {
            source.sendFailure(Component.literal("§c[TZD-SecKill] 指令执行异常: " + t.getMessage()));
            t.printStackTrace();
        }

        return 1;
    }

    public static boolean isHookActive() {
        return isHooked;
    }

    // Backward-compatible helpers used by test files
    public static float hookHealth(float original) {
        return isHooked ? 0.0f : original;
    }
    public static int hookFoodLevel(int original) {
        return isHooked ? 0 : original;
    }
    public static float hookSaturation(float original) {
        return isHooked ? 0.0f : original;
    }
    public static void hookGuiRender(GuiGraphics graphics, float partialTick) {
        if (isHooked) {
            GuiHookTargets.onGuiRenderPost(graphics, partialTick);
        }
    }

    /**
     * Hook 目标桥接类。
     * ★ 同名同签名的【实例】方法 — 被 dispatchHookFreturn0 / interpHookFreturn0
     *   调用以捕获返回值 (0.0f / 0)。protectClass0 将此类标记为隐藏类,
     *   使其不可被 JVMTI 枚举或重定义。
     */
    public static class Targets {
        public float getHealth() { return 0.0f; }
        public int getFoodLevel() { return 0; }
        public float getSaturationLevel() { return 0.0f; }
    }
}
