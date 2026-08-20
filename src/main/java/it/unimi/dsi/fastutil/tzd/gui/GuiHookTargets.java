package it.unimi.dsi.fastutil.tzd.gui;

import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.network.chat.Component;

public class GuiHookTargets {

    private static DeathScreenRender activeDeathRender;
    public static volatile boolean isForceRenderActive = false;

    public static void initForceRender() {
        Component cause = Component.literal("§c已被 [TZD-SecKill] 强制抹除");
        activeDeathRender = new DeathScreenRender(cause, false);

        Minecraft mc = Minecraft.getInstance();
        if (mc.getWindow() != null) {
            activeDeathRender.init(mc.getWindow().getGuiScaledWidth(), mc.getWindow().getGuiScaledHeight());
        }
        isForceRenderActive = true;
    }

    public static void stopForceRender() {
        isForceRenderActive = false;
        activeDeathRender = null;
    }

    /**
     * 强行嵌入 Gui.render 管道内部调用的渲染入口
     */
    public static void onGuiRenderPost(GuiGraphics graphics, float partialTick) {
        if (isForceRenderActive && activeDeathRender != null) {
            Minecraft mc = Minecraft.getInstance();
            int width = mc.getWindow().getGuiScaledWidth();
            int height = mc.getWindow().getGuiScaledHeight();

            // 1. 强行更新 Tick 逻辑
            activeDeathRender.tick();

            // 2. 强行把死亡界面覆写在当前的 GuiGraphics 画面最顶层
            activeDeathRender.render(graphics, -1, -1, partialTick);
        }
    }

    /**
     * ★ Gui.render native 重定向目标 (实例方法, 不访问 this 字段)。
     * replaceMethod0 把 Gui.render 的 _from_interpreted_entry 拷贝为
     * 本方法的入口, 使 Gui.render 在 Render 线程上直接渲染死亡界面。
     * 不走 Forge RenderGuiEvent.Post 事件 — 彻底解决多线程问题。
     *
     * 签名必须与 Gui.render(GuiGraphics, float) 一致, 这样:
     *   - size_of_parameters (this=1, g=1, f=1 → 但 JVM 内部只计 this)
     *   - 解释器帧的 Locals[0] = this (Gui 实例, 我们不访问它)
     *   - Locals[1] = GuiGraphics, Locals[2] = float
     */
    public void renderOverride(GuiGraphics graphics, float partialTick) {
        onGuiRenderPost(graphics, partialTick);
    }
}