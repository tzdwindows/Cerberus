package it.unimi.dsi.fastutil.tzd.gui;

import com.google.common.collect.Lists;
import java.util.List;
import net.minecraft.ChatFormatting;
import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.components.AbstractWidget;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.screens.ConfirmScreen;
import net.minecraft.client.gui.screens.GenericDirtMessageScreen;
import net.minecraft.client.gui.screens.TitleScreen;
import net.minecraft.network.chat.ClickEvent;
import net.minecraft.network.chat.CommonComponents;
import net.minecraft.network.chat.Component;
import net.minecraft.network.chat.Style;

/**
 * 针对 Native/Client 极速场景重构的死亡界面控制器与渲染器
 */
public class DeathScreenRender {

    private final Minecraft minecraft = Minecraft.getInstance();

    private int delayTicker = 0;
    private Component causeOfDeath;
    private boolean hardcore;
    private Component deathScore;

    private final List<Button> exitButtons = Lists.newArrayList();
    private Button exitToTitleButton;

    private int width;
    private int height;
    private boolean initialized = false;

    public DeathScreenRender(Component causeOfDeath, boolean hardcore) {
        this.causeOfDeath = causeOfDeath;
        this.hardcore = hardcore;
    }

    /**
     * 对应原版 init()，可以在屏幕尺寸变更或手动重置时调用
     */
    public void init(int screenWidth, int screenHeight) {
        this.width = screenWidth;
        this.height = screenHeight;
        this.delayTicker = 0;
        this.exitButtons.clear();

        Component respawnBtnText = this.hardcore
                ? Component.translatable("deathScreen.spectate")
                : Component.translatable("deathScreen.respawn");

        // 1. 复刻 Respawn / Spectate 按钮逻辑
        Button respawnButton = Button.builder(respawnBtnText, (btn) -> {
            if (this.minecraft.player != null) {
                // 触发客户端发送 Respawn 数据包
                this.minecraft.player.respawn();
            }
            btn.active = false;
        }).bounds(this.width / 2 - 100, this.height / 4 + 72, 200, 20).build();

        this.exitButtons.add(respawnButton);

        // 2. 复刻 Exit To Title 按钮逻辑
        this.exitToTitleButton = Button.builder(Component.translatable("deathScreen.titleScreen"), (btn) -> {
            if (this.minecraft.getReportingContext() != null) {
                this.minecraft.getReportingContext().draftReportHandled(
                        this.minecraft,
                        this.minecraft.screen,
                        this::handleExitToTitleScreen,
                        true
                );
            } else {
                this.handleExitToTitleScreen();
            }
        }).bounds(this.width / 2 - 100, this.height / 4 + 96, 200, 20).build();

        this.exitButtons.add(this.exitToTitleButton);

        // 默认按原版 20 tick 冷却机制关闭响应
        this.setButtonsActive(false);

        // 3. 构建分数显示文本
        int score = (this.minecraft.player != null) ? this.minecraft.player.getScore() : 0;
        this.deathScore = Component.translatable("deathScreen.score")
                .append(": ")
                .append(Component.literal(Integer.toString(score)).withStyle(ChatFormatting.YELLOW));

        this.initialized = true;
    }

    /**
     * Tick 状态更新（原版 20 tick 防误触延迟）
     */
    public void tick() {
        if (!initialized) return;

        ++this.delayTicker;
        if (this.delayTicker == 20) {
            this.setButtonsActive(true);
        }
    }

    /**
     * 复刻 render() 方法：绘制背景渐变、缩放死亡标题、死亡原因与得分
     */
    public void render(GuiGraphics graphics, int mouseX, int mouseY, float partialTick) {
        if (!initialized) return;

        // 1. 绘制半透明红/黑渐变背景
        graphics.fillGradient(0, 0, this.width, this.height, 1615855616, -1602211792);

        // 2. 放大 2.0x 渲染死亡主标题
        graphics.pose().pushPose();
        graphics.pose().scale(2.0F, 2.0F, 2.0F);

        Component title = Component.translatable(this.hardcore ? "deathScreen.title.hardcore" : "deathScreen.title");
        graphics.drawCenteredString(this.minecraft.font, title, this.width / 2 / 2, 30, 0xFFFFFF);

        graphics.pose().popPose();

        // 3. 渲染死亡原因文本
        if (this.causeOfDeath != null) {
            graphics.drawCenteredString(this.minecraft.font, this.causeOfDeath, this.width / 2, 85, 0xFFFFFF);
        }

        // 4. 渲染分数
        if (this.deathScore != null) {
            graphics.drawCenteredString(this.minecraft.font, this.deathScore, this.width / 2, 100, 0xFFFFFF);
        }

        // 5. 渲染文本 Hover 悬浮提示（例如 URL 链接等 Style）
        if (this.causeOfDeath != null && mouseY > 85 && mouseY < 85 + 9) {
            Style style = this.getClickedComponentStyleAt(mouseX);
            if (style != null) {
                graphics.renderComponentHoverEffect(this.minecraft.font, style, mouseX, mouseY);
            }
        }

        // 6. 渲染所有注册的按钮控件
        for (Button button : this.exitButtons) {
            button.render(graphics, mouseX, mouseY, partialTick);
        }

        // 7. 渲染草稿举报提示图表（若有）
        if (this.exitToTitleButton != null && this.minecraft.getReportingContext() != null
                && this.minecraft.getReportingContext().hasDraftReport()) {
            graphics.blit(
                    AbstractWidget.WIDGETS_LOCATION,
                    this.exitToTitleButton.getX() + this.exitToTitleButton.getWidth() - 17,
                    this.exitToTitleButton.getY() + 3,
                    182, 24, 15, 15
            );
        }
    }

    /**
     * 复刻 mouseClicked 事件（响应原因文本中的点击事件如超链接）
     */
    public boolean mouseClicked(double mouseX, double mouseY, int button) {
        // 先检测按钮点击
        for (Button btn : this.exitButtons) {
            if (btn.mouseClicked(mouseX, mouseY, button)) {
                return true;
            }
        }

        // 检测文本点击（Chat Click Event）
        if (this.causeOfDeath != null && mouseY > 85.0D && mouseY < 94.0D) {
            Style style = this.getClickedComponentStyleAt((int) mouseX);
            if (style != null && style.getClickEvent() != null && style.getClickEvent().getAction() == ClickEvent.Action.OPEN_URL) {
                // 如果需要执行 ClickEvent 激活，可以通过当前 Screen 进行上下文解包
                if (this.minecraft.screen != null) {
                    this.minecraft.screen.handleComponentClicked(style);
                }
                return true;
            }
        }

        return false;
    }

    private void handleExitToTitleScreen() {
        if (this.hardcore) {
            this.exitToTitleScreen();
        } else {
            ConfirmScreen confirmScreen = new ConfirmScreen(
                    (confirmed) -> {
                        if (confirmed) {
                            this.exitToTitleScreen();
                        } else {
                            if (this.minecraft.player != null) {
                                this.minecraft.player.respawn();
                            }
                            this.minecraft.setScreen(null);
                        }
                    },
                    Component.translatable("deathScreen.quit.confirm"),
                    CommonComponents.EMPTY,
                    Component.translatable("deathScreen.titleScreen"),
                    Component.translatable("deathScreen.respawn")
            );

            this.minecraft.setScreen(confirmScreen);
            confirmScreen.setDelay(20);
        }
    }

    private void exitToTitleScreen() {
        if (this.minecraft.level != null) {
            this.minecraft.level.disconnect();
        }

        this.minecraft.clearLevel(new GenericDirtMessageScreen(Component.translatable("menu.savingLevel")));
        this.minecraft.setScreen(new TitleScreen());
    }

    private void setButtonsActive(boolean active) {
        for (Button button : this.exitButtons) {
            button.active = active;
        }
    }

    private Style getClickedComponentStyleAt(int mouseX) {
        if (this.causeOfDeath == null) {
            return null;
        } else {
            int textWidth = this.minecraft.font.width(this.causeOfDeath);
            int startX = this.width / 2 - textWidth / 2;
            int endX = this.width / 2 + textWidth / 2;

            return (mouseX >= startX && mouseX <= endX)
                    ? this.minecraft.font.getSplitter().componentStyleAtWidth(this.causeOfDeath, mouseX - startX)
                    : null;
        }
    }

    // --- Accessor & Mutator ---
    public boolean isInitialized() {
        return initialized;
    }

    public void setCauseOfDeath(Component cause) {
        this.causeOfDeath = cause;
    }
}