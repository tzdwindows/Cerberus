function initializeCoreMod() {
    var Opcodes = Java.type('org.objectweb.asm.Opcodes');
    var InsnList = Java.type('org.objectweb.asm.tree.InsnList');
    var VarInsnNode = Java.type('org.objectweb.asm.tree.VarInsnNode');
    var MethodInsnNode = Java.type('org.objectweb.asm.tree.MethodInsnNode');
    var ASMAPI = Java.type('net.minecraftforge.coremod.api.ASMAPI');
    var hooks = 'it/unimi/dsi/fastutil/tzd/SekKillMod';

    function wrapReturns(method, returnOpcode, hookName, hookDescriptor) {
        var count = 0;
        var instruction = method.instructions.getFirst();
        while (instruction !== null) {
            var next = instruction.getNext();
            if (instruction.getOpcode() === returnOpcode) {
                method.instructions.insertBefore(instruction, new MethodInsnNode(
                    Opcodes.INVOKESTATIC, hooks, hookName, hookDescriptor, false));
                count++;
            }
            instruction = next;
        }
        if (count === 0) {
            throw new Error('[TZD-SecKill] No return opcode found in ' + method.name + method.desc);
        }
        return method;
    }

    return {
        livingHealth: {
            target: {
                type: 'METHOD',
                class: 'net.minecraft.world.entity.LivingEntity',
                methodName: 'm_21223_',
                methodDesc: '()F'
            },
            transformer: function(method) {
                return wrapReturns(method, Opcodes.FRETURN, 'hookHealth', '(F)F');
            }
        },
        foodLevel: {
            target: {
                type: 'METHOD',
                class: 'net.minecraft.world.food.FoodData',
                methodName: 'm_38702_',
                methodDesc: '()I'
            },
            transformer: function(method) {
                return wrapReturns(method, Opcodes.IRETURN, 'hookFoodLevel', '(I)I');
            }
        },
        saturation: {
            target: {
                type: 'METHOD',
                class: 'net.minecraft.world.food.FoodData',
                methodName: 'm_38722_',
                methodDesc: '()F'
            },
            transformer: function(method) {
                return wrapReturns(method, Opcodes.FRETURN, 'hookSaturation', '(F)F');
            }
        },
        guiRender: {
            target: {
                type: 'METHOD',
                class: 'net.minecraft.client.gui.Gui',
                methodName: 'm_280421_',
                methodDesc: '(Lnet/minecraft/client/gui/GuiGraphics;F)V'
            },
            transformer: function(method) {
                var count = 0;
                var instruction = method.instructions.getFirst();
                while (instruction !== null) {
                    var next = instruction.getNext();
                    if (instruction.getOpcode() === Opcodes.RETURN) {
                        var tail = new InsnList();
                        tail.add(new VarInsnNode(Opcodes.ALOAD, 1));
                        tail.add(new VarInsnNode(Opcodes.FLOAD, 2));
                        tail.add(new MethodInsnNode(Opcodes.INVOKESTATIC, hooks, 'hookGuiRender',
                            '(Lnet/minecraft/client/gui/GuiGraphics;F)V', false));
                        method.instructions.insertBefore(instruction, tail);
                        count++;
                    }
                    instruction = next;
                }
                if (count === 0) {
                    throw new Error('[TZD-SecKill] Gui.render has no RETURN');
                }
                return method;
            }
        }
    };
}
