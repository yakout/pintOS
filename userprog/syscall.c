#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "../lib/debug.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "threads/synch.h"
#include "filesys/filesys.h"


static void syscall_handler (struct intr_frame *);
static tid_t exec_handler(struct intr_frame *f);
static bool remove_handler(struct intr_frame *f);
static int read_handler(struct intr_frame *f);
static void tell_handler(struct intr_frame *f);
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static uint32_t get_parameter(struct intr_frame *f , int number);
static bool valid_string_pointer(char* str);
static bool valid_string(const char* str);


static void *to_kernel_addr (void *uaddr);
static struct file *get_file_by_fd (int fd);

void exit (int status);
void halt(void);
bool create (const char *file, unsigned initial_size);
int filesize (int fd);
void seek (int fd, unsigned position);


struct lock fs_lock;
struct lock fd_lock;

extern struct list waiters_list;
extern struct waiter;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&fs_lock);
  lock_init(&fd_lock);
  list_init(&waiters_list);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
 
 /* identify system call */
int *p=f->esp;

 switch(*p) {
 	case SYS_EXEC:
 		f->eax = exec_handler(PARM(p,PARM_ONE));
 		break;
 	case SYS_REMOVE:
 		f->eax = remove_handler(PARM(p,PARM_ONE));
 		break;
 	case SYS_READ:
 		f->eax = read_handler(PARM(p,PARM_ONE),PARM(p,PARM_TWO),PARM(p,PARM_THREE));
 		break;
 	case SYS_TELL:
 		tell_handler(PARM(p,PARM_ONE));
 		break;
 	case SYS_EXIT:
 		/* terminates the current user program */
 		printf("\nexit status = %d\n", *(p+1) );
 		/* update the status of running */
 		int status = *(p+1);
 		exit(status);
 		break;
 	case SYS_WAIT:
 		/* waits for a child process pid and retrieves the child's exit status */
 		/* obtain p_id of process to wait for */
 		printf("\nchild ID = %d\n", *(p+1) );
 		tid_t child_tid = *(p+1);
 		int child_status = process_wait(child_tid);
 		f->eax=child_status;
 		break;
 	case SYS_CLOSE:
 		// TODO
 		break;
 	case SYS_HALT:
 		halt();
 		break;
 	case SYS_WRITE:
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
 		break;
 	case SYS_OPEN:
 		f->eax = open_handler(PARM(p,PARM_ONE));
 		break;
 	default:
 		exit(-1);
 }

}

void
halt( void ) 
{
	/* terminates Pintos by calling shutdown_power_off() */
 	shutdown_power_off ();
}


void
exit (int status)
{
	update_process_waiters_list (status);
 	thread_exit ();
}

/* Creates a new file called file initially initial_size bytes in size.
 Returns true if successful, false otherwise.  */
bool
create (const char *file, unsigned initial_size)
{
	bool success;
	file = to_kernel_addr (file);

	lock_acquire (&fs_lock);
	success = filesys_create (file, initial_size);
	lock_release (&fs_lock);

	return success;
}


/* Returns the size, in bytes, of the file open as fd. */
int 
filesize (int fd)
{
  lock_acquire (&fs_lock);
  struct file *f = get_file_by_fd (fd);
  lock_release (&fs_lock);

  if (f == NULL)
    return 0;

  lock_acquire (&fs_lock);
  int size = file_length (f);
  lock_release (&fs_lock);
  return size;
}

/* Changes the next byte to be read or written in open file fd to position,
 expressed in bytes from the beginning of the file. */
static void 
seek (int fd, unsigned position)
{
  if (position < 0)
    return;

  lock_acquire (&fs_lock);
  struct file *f = get_file_by_fd (fd);
  if (f == NULL || position < 0)
    {
      lock_release (&fs_lock);
      return;
    }
  file_seek (f, position);
  lock_release (&fs_lock);
}


/* This function maps uaddr to kaddr. */
static void
to_kernel_addr(void *uaddr)
{
	struct thread *curr = thread_current ();
	void *kaddr = NULL;
	if (is_user_vaddr(uaddr))
	{
		kaddr = pagedir_get_page (curr->pagedir, uaddr);
	} 
	if (kaddr == NULL)
	{
		// uaddr is unmapped
		exit (-1);
	}
	return kaddr;
}


static tid_t
exec_handler(char* command_line)
{
	
	// check the pointer to be in user memory
	if(!valid_string(command_line)){
		f->eax = -1;
		return;
	}

 	// no interrupts until parent finishes
	lock_acquire (&fs_lock);					
	
	// apply spwaning 
	tid_t pid = process_execute (command_line);
	
	// you can continue on
	lock_release(&fs_lock);
	
	// return id
	return pid;
}

static int
open_handler(const char* file_name)
{

	if (!valid_string (file_name))
	{
		return -1 ;	
	}

	lock_acquire(&fs_lock);

	struct file* open_file = filesys_open (file_name);

	lock_release(&fs_lock);

	if(open_file == NULL)
	{
		return -1 ;
	}

	// note that you should free the file_entry struct when close.
	struct file_entry* entry = malloc (sizeof (*entry));
	entry->fd = allocate_fd ();
	entry->file = open_file;
	list_push_back (&thread_current ()->open_file_table, &entry->hock);
	
	return entry->fd;
}

static bool
remove_handler(const char* file_name)
{	
	// check for validity.
	if (!valid_string (file_name))
	{
		return false;
	}
	lock_acquire(&fs_lock);
	
	// remove it
	bool r_value = filesys_remove (file_name);
	
	lock_release(&fs_lock);

	return r_value;
}

static int
read_handler(int fd, void *buffer, unsigned size)
{

	if(fd == 0){
		// read from keyboard
		int i = 0;
		for(;i<size;i++){
			(uint8_t)buffer[i] = input_getc();
		}
		return size;
	}

	lock_acquire(&fs_lock);

	struct file* current_file = get_file_by_fd(fd);

	if(current_file == NULL){
		return -1;
	}
	int r_value = file_read(current_file,buffer,size);
	
	lock_release(&fs_lock);

	return r_value;
}

static void 
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
allocate_fd()
{
	lock_acquire(&fd_lock);
	int fd = thread_current()->current_fd + 1;
	lock_release(&fd_lock);
	return fd;
}

static int
tell_handler(int fd)
{

	lock_acquire(&fs_lock);
	
	struct file* current_file = get_file_by_fd (fd);
	if (current_file == NULL)
	{
		return -1;
	}
	int r_value = file_tell(current_file);
	
	lock_release(&fs_lock);

	return r_value;
}

static bool
valid_string (const char* str)
{

	if(is_kernel_vaddr(str)){
		return false;
	}
	if(!valid_string_pointer(str)){
		return false;
	}
	return true;
}

static uint32_t
get_parameter (struct intr_frame *f , int number)
{
	int *p = f->esp;
	return *(p+number);
}


/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}
 
/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}



static bool
valid_string_pointer(char *str)
{
	while(get_user((uint8_t*)str) != -1 && *str!='\0'){
		str++;
	}
	return *str=='\0';
}

/* return file pointer crossponding to given fd. */
static struct file *get_file_by_fd (int fd)
{
	
  struct list_elem *e;

  for (e = list_begin (&thread_current()->open_file_table);
  	   e != list_end (&thread_current()->open_file_table);
       e = list_next (e))
    {
      struct file_entry *entry = list_entry (e, struct file_entry, hock);
      if(entry->fd==fd){
      	return entry->file;
      }
    }
  return NULL;
}
