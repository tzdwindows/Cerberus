package it.unimi.dsi.fastutil.tzd.gui;

import com.mojang.blaze3d.pipeline.RenderTarget;
import com.mojang.blaze3d.pipeline.TextureTarget;
import com.mojang.blaze3d.systems.RenderSystem;
import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.GuiGraphics;

public class OffscreenDeathRenderer {

    private RenderTarget offscreenBuffer;
    private DeathScreenRender deathRender;

    public OffscreenDeathRenderer(DeathScreenRender deathRender) {
        this.deathRender = deathRender;
    }

    /**
     * 执行离屏渲染的核心方法
     * @param width 缓冲区宽度 (例如 1920)
     * @param height 缓冲区高度 (例如 1080)
     * @return 渲染完毕的 RenderTarget 实例
     */
    public RenderTarget renderToBuffer(int width, int height) {
        Minecraft mc = Minecraft.getInstance();

        // 1. 确保在 RenderSystem / OpenGL 主线程环境运行
        if (!RenderSystem.isOnRenderThread()) {
            RenderSystem.recordRenderCall(() -> executeRender(mc, width, height));
        } else {
            executeRender(mc, width, height);
        }

        return this.offscreenBuffer;
    }

    private void executeRender(Minecraft mc, int width, int height) {
        // 2. 初始化离屏 FBO 缓冲区
        if (this.offscreenBuffer == null) {
            // 创建支持深度缓冲的 Framebuffer 纹理
            this.offscreenBuffer = new TextureTarget(width, height, true, Minecraft.ON_OSX);
        } else if (this.offscreenBuffer.width != width || this.offscreenBuffer.height != height) {
            this.offscreenBuffer.resize(width, height, Minecraft.ON_OSX);
        }

        // 3. 保存主渲染窗口的 Framebuffer 引用，避免打乱 Minecraft 主画面
        RenderTarget mainBuffer = mc.getMainRenderTarget();

        try {
            // 4. 绑定到离屏缓冲区并清屏
            this.offscreenBuffer.bindWrite(true);
            RenderSystem.clear(256, Minecraft.ON_OSX); // Clear Depth Buffer

            // 5. 初始化 DeathScreenRender 尺寸
            if (!this.deathRender.isInitialized()) {
                this.deathRender.init(width, height);
            }

            // 6. 构造 GuiGraphics 离屏绘制上下文
            GuiGraphics graphics = new GuiGraphics(mc, mc.renderBuffers().bufferSource());

            // 7. 离屏绘制 DeathScreen 内容
            this.deathRender.render(graphics, -1, -1, 0.0f);

            // 刷新 RenderType 批处理队列
            graphics.flush();

        } finally {
            // 8. 恢复 Minecraft 主渲染管道 Bind，解绑离屏 Buffer
            mainBuffer.bindWrite(true);
        }
    }

    public void destroy() {
        if (this.offscreenBuffer != null) {
            this.offscreenBuffer.destroyBuffers();
            this.offscreenBuffer = null;
        }
    }

    public RenderTarget getOffscreenBuffer() {
        return offscreenBuffer;
    }
}