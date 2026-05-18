package com.memhunter.attach;

import com.sun.tools.attach.VirtualMachine;
import com.sun.tools.attach.VirtualMachineDescriptor;

import java.util.List;

public class JvmProcessLister {

    public void printAll() {
        List<VirtualMachineDescriptor> list = VirtualMachine.list();
        System.out.println("PID\tDisplay");
        for (VirtualMachineDescriptor vm : list) {
            System.out.println(vm.id() + "\t" + vm.displayName());
        }
    }
}
