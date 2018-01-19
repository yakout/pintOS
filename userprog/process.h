#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"


/* list of processes waiting on child */
/*struct list waiters_list;

struct waiter {

	tid_t parent_tid;
	tid_t child_tid;
	int child_exit_status;
	struct list_elem entry_hook;
	
};*/

struct list signal_list;


struct child_signal {

	struct list_elem hook;
	tid_t child_tid;
	int child_exit_status;

};



tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
