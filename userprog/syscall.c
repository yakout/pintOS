#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "../lib/debug.h"
#include "userprog/process.h"

static void syscall_handler (struct intr_frame *);
extern struct list waiters_list;
extern struct waiter;

void
syscall_init (void) 
{
	list_init(&waiters_list);
  	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{

	/*int call_no=-1;
	asm volatile
		("pop word ptr %[num]"
		: 
     	: [num] "i" (call_no)
 		: "memory");*/

	/* identify system call */
	int *p=f->esp;

	/* 01 - system halt */
	if(*p == SYS_HALT){
 		/* terminates Pintos by calling shutdown_power_off() */
 		shutdown_power_off();
 	}


 	/* 02 - process exit */
	if(*p == SYS_EXIT){
 		/* terminates the current user program */
 		printf("\nexit status = %d\n", *(p+1) );
 		/* update the status of running */
 		int status = *(p+1);
  		update_process_waiters_list(status);
 		thread_exit ();
 	}

 	/* 03 - create new process */
	if(*p == SYS_EXEC){
 		/* spawn new child process */;
 		
 		// 01 cmd arguments
		tid_t tid = process_execute(*(p+1));
 		// 02 return process id
 		f->eax=tid;
 	}


	/* 04 - system wait */
	if(*p == SYS_WAIT){
 		/* waits for a child process pid and retrieves the child's exit status */
 		/* obtain p_id of process to wait for */
 		printf("\nchild ID = %d\n", *(p+1) );
 		tid_t child_tid = *(p+1);

 		int child_status = process_wait(child_tid);

 		f->eax=child_status;
 		
 	}


 	/* 05 - write syscall */
 	if(*p == SYS_WRITE){
 		// retrieve sys call type (console or disk)
 		int type = *(p+1);
 		if(type==1)
 		{
 			/* write to console */
 			printf("%s\n", *(p+2) );
 		}
 		else
 		{
 			/* write to disk */
 		}
 		
 	}


 	if(*p == SYS_OPEN)
 	{
	 	const char* file_name = (char*) *(p+1);
		struct file* open_file = filesys_open (file_name);
		struct file_entry* entry = malloc(sizeof(*entry));
		entry->fd = allocate_fd();
		entry->file = open_file;
		list_push_back(&thread_current()->open_file_table,&entry->hock);
		f->eax = entry->fd;
 	}

}



void
update_process_waiters_list(int status)
{
  tid_t current_tid = thread_current()->tid;

  struct list_elem *e;
  for (e = list_begin (&waiters_list); e != list_end (&waiters_list);
       e = list_next (e))
    {
      struct waiter *entry = list_entry (e, struct waiter, entry_hook);
      if (entry->child_tid == current_tid)
      {
        entry->child_exit_status=status;
      }

    }

}

static int
allocate_fd(){
	return thread_current()->current_fd+=1;
}