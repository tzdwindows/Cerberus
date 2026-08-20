// Architect: tzdwindows 7
package it.unimi.dsi.fastutil.tzd.seckill;

import net.minecraft.client.Minecraft;
import net.minecraft.world.entity.player.Player;
import net.minecraftforge.common.MinecraftForge;
import net.minecraftforge.eventbus.api.IEventBus;

import java.util.UUID;

public final class MinecraftForgeRef {
    static final IEventBus EVENT_BUS_REF = MinecraftForge.EVENT_BUS;
    static IEventBus EVENT_BUS = EVENT_BUS_REF;

    static UUID getLocalPlayerUUID() {
        try {
            Minecraft mc = Minecraft.getInstance();
            if (mc == null) return null;
            Player p = mc.player;
            return (p == null) ? null : p.getUUID();
        } catch (Throwable t) { return null; }
    }
}
