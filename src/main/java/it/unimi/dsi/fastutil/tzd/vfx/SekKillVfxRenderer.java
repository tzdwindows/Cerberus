// Architect: tzdwindows 7
package it.unimi.dsi.fastutil.tzd.vfx;

import net.minecraftforge.api.distmarker.Dist;
import net.minecraftforge.api.distmarker.OnlyIn;
import net.minecraftforge.client.event.RenderLevelStageEvent;

@OnlyIn(Dist.CLIENT)
public final class SekKillVfxRenderer {
    private static long lastKillTime = 0L;
    private static double killX, killY, killZ;

    public static void triggerKillEffect(double x, double y, double z) {
        lastKillTime = System.currentTimeMillis();
        killX = x; killY = y; killZ = z;
    }

    public static void onRenderLevel(RenderLevelStageEvent event) {
        if (event.getStage() != RenderLevelStageEvent.Stage.AFTER_PARTICLES) return;
        long dt = System.currentTimeMillis() - lastKillTime;
        if (dt < 0 || dt > 1200) return;
        // Visual effect placeholder: actual GL rendering would go here.
        // For now we log to confirm the hook is active.
    }
}
