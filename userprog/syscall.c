#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "../lib/debug.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);



static void *to_kernel_addr (void *uaddr);
static struct file *get_file_by_fd (int fd UNUSED);

void exit (int status);
bool create (const char *file, unsigned initial_size);
int filesize (int fd);
void seek (int fd, unsigned position);



static struct lock fs_lock;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{


 int *p=f->esp;
 if(*p == SYS_WRITE){
 	printf("blahfhdhdhdhfh");
 	printf("%s\n", *(p+6));
  }


  thread_exit ();
}


/* Terminates the current user program, returning status to the kernel */
void
exit (int status)
{
  struct thread *cur = thread_current ();
  // cur->exit_status = status;
  printf ("%s: exit(%d)\n", cur->name, status);
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
void 
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


/* return file pointer crossponding to given fd. */
struct file *
get_file_by_fd (int fd UNUSED)
{
	// TODO
}

