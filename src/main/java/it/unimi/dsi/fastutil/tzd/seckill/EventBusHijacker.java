// Architect: tzdwindows 7
package it.unimi.dsi.fastutil.tzd.seckill;

import net.minecraft.world.damagesource.DamageSource;
import net.minecraft.world.entity.Entity;
import net.minecraft.world.entity.LivingEntity;
import net.minecraft.world.entity.player.Player;
import net.minecraftforge.event.entity.living.LivingDamageEvent;
import net.minecraftforge.event.entity.living.LivingHurtEvent;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

public final class EventBusHijacker {
    private static final AtomicBoolean installed = new AtomicBoolean(false);
    private static volatile boolean seckillActive = true;

    public static void install() {
        if (installed.getAndSet(true)) return;
        System.err.println("[TZD-SecKill] EventBusHijacker installed (priority=HIGHEST)");
        silenceHostileHandlers();
    }

    public static void setSeckillActive(boolean v) { seckillActive = v; }

    public static void onLivingHurt(LivingHurtEvent event) {
        if (!seckillActive) return;
        try {
            LivingEntity target = event.getEntity();
            DamageSource source = event.getSource();
            Entity attacker = source.getEntity();

            if (attacker instanceof Player player && player.getUUID().equals(getLocalPlayerUUID())) {
                if (target != null && !target.equals(player)) {
                    float original = event.getAmount();
                    event.setAmount(Float.MAX_VALUE);
                    System.err.println("[TZD-SecKill] attack amplified: " + original + " -> MAX  target=" + target.getType());
                }
            } else if (target instanceof Player player && player.getUUID().equals(getLocalPlayerUUID())) {
                event.setAmount(0.0F);
                System.err.println("[TZD-SecKill] defense neutralized: incoming damage -> 0");
            }
        } catch (Throwable t) {
            System.err.println("[TZD-SecKill] onLivingHurt error: " + t);
        }
    }

    public static void onLivingDamage(LivingDamageEvent event) {
        if (!seckillActive) return;
        try {
            LivingEntity target = event.getEntity();
            DamageSource source = event.getSource();
            Entity attacker = source.getEntity();

            if (attacker instanceof Player player && player.getUUID().equals(getLocalPlayerUUID())) {
                if (target != null && !target.equals(player)) {
                    event.setAmount(Float.MAX_VALUE);
                }
            } else if (target instanceof Player player && player.getUUID().equals(getLocalPlayerUUID())) {
                event.setAmount(0.0F);
            }
        } catch (Throwable t) {
            System.err.println("[TZD-SecKill] onLivingDamage error: " + t);
        }
    }

    @SuppressWarnings("unchecked")
    private static void silenceHostileHandlers() {
        try {
            Class<?> forgeBusClass = Class.forName("net.minecraftforge.eventbus.EventBus");
            Field listenersField = forgeBusClass.getDeclaredField("listeners");
            listenersField.setAccessible(true);
            Object bus = MinecraftForgeRef.EVENT_BUS;
            Object listeners = listenersField.get(bus);
            int scanned = (listeners == null) ? 0 : java.lang.reflect.Array.getLength(listeners);
            System.err.println("[TZD-SecKill] scanned Forge EventBus listener array size=" + scanned);
        } catch (Throwable t) {
            System.err.println("[TZD-SecKill] hostile handler scan skipped: " + t.getMessage());
        }
    }

    private static java.util.UUID getLocalPlayerUUID() {
        try {
            return MinecraftForgeRef.getLocalPlayerUUID();
        } catch (Throwable t) { return null; }
    }
}
