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

static void halt_handler ();
void exit_handler (int status);
static tid_t exec_handler (const char *cmd_line);
static int wait_handler (tid_t pid);

static bool create_handler (const char *file, unsigned initial_size);
static bool remove_handler (const char *file);

static int open_handler (const char* file);
static void close_handler (int fd);

static int read_handler (int fd, void *buffer, unsigned size);
static int write_handler (int fd, void *buffer, unsigned size);


static void seek_handler (int fd, unsigned position);
static unsigned tell_handler(int fd);
static int filesize_handler(int fd);


static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static uint32_t get_parameter(struct intr_frame *f , int number);
static bool valid_pointer(void* pt);
static bool valid_string(char* str);

static struct file_entry *get_file_entry_by_fd (int fd);
static void signal_parent(int status);
static int allocate_fd();
static bool to_kernel_addr (void *uaddr);
static bool is_executable(char *file_name);


struct lock fs_lock;
extern struct list signal_list;

extern struct lock sync_dummy;
extern struct condition sync_cond;
extern bool process_creation_successful;


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&fs_lock);
  list_init(&signal_list);
  lock_init(&sync_dummy);
  cond_init(&sync_cond);
}

static void verify_address(struct intr_frame *f,uint8_t bytes)
{

    uint8_t i=0;
    uint8_t *pt = f->esp;
	for(; i<bytes; i++)
	{
		if(get_user((pt+i)) == -1)
		{
			exit_handler(-1);
		}
	}
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	int *p=f->esp;
	/* check valid system call address */
	if(!valid_pointer(f->esp))
	{
		exit_handler(-1);
	}
	switch(*p) {
	 	case SYS_HALT:
	 		verify_address(f,4);
	 		halt_handler();
	 		break;
	 	case SYS_EXIT:
	 		verify_address(f,8);
	 		exit_handler(PARM(p,PARM_ONE));
	 		break;
	 	case SYS_EXEC:
	 		verify_address(f,8);
	 		f->eax = exec_handler(PARM(p,PARM_ONE));
	 		break;
	 	case SYS_WAIT:
	 		verify_address(f,8);
	 		f->eax=wait_handler(PARM(p,PARM_ONE));
	 		break;
	 	case SYS_CREATE:
	 		verify_address(f,12);
	 		f->eax=create_handler(PARM(p,PARM_ONE), PARM(p,PARM_TWO));
	 		break;
	 	case SYS_REMOVE:
	 		verify_address(f,8);
	 		f->eax = remove_handler(PARM(p,PARM_ONE));
	 		break;
	 	case SYS_OPEN:
	 		verify_address(f,8);
	 		f->eax = open_handler(PARM(p,PARM_ONE));
	 		break;
	 	case SYS_CLOSE:
	 		verify_address(f,8);
	 		close_handler(PARM(p, PARM_ONE));
	 		break;
	 	case SYS_READ:
	 		verify_address(f,16);
	 		f->eax = read_handler(PARM(p,PARM_ONE),PARM(p,PARM_TWO),PARM(p,PARM_THREE));
	 		break;
	 	case SYS_WRITE:
	 		verify_address(f,16);
	 		f->eax = write_handler(PARM(p,PARM_ONE),PARM(p,PARM_TWO),PARM(p,PARM_THREE));
	 		break;
	 	case SYS_SEEK:
	 		verify_address(f,12);
	 		seek_handler(PARM(p,PARM_ONE),PARM(p,PARM_TWO));
	 		break;
	 	case SYS_TELL:
	 		verify_address(f,8);
	 		f->eax = tell_handler(PARM(p,PARM_ONE));
	 		break;
	 	case SYS_FILESIZE:
	 		verify_address(f,8);
	 		f->eax = filesize_handler(PARM(p,PARM_ONE));
	 		break;
	 	default:
	 		exit_handler(-1);
 	}

}



static void
halt_handler( void ) 
{
	/* terminates Pintos by calling shutdown_power_off() */
 	shutdown_power_off ();
}




void
exit_handler (int status)
{

	printf ("%s: exit(%d)\n", thread_current()->name, status);
	file_close(thread_current()->me_as_executable);
 	signal_parent (status);
 	//printf("\nsignaled parent\n");
 	thread_exit ();
}

static tid_t
exec_handler(const char* cmd_line)
{
	/* check the pointer to be in user memory */
	if(!valid_string(cmd_line)){
		return -1;
	}
 	// no interrupts until parent finishes
	lock_acquire (&fs_lock);

	// apply spwaning 
	tid_t pid = process_execute (cmd_line);
	/* process syncing between child and parent */
	/* parent just woke from sleep waiting for child to finish load */
	// you can continue on
	lock_release(&fs_lock);
	// return id

	//printf("\nreturn pid : %d\n", pid);

	return pid;
}

static int
wait_handler (tid_t pid)
{
	/* check invalid memory reference */
	/*if(!valid_pointer(&pid)){
		return -1;
	}*/
	return process_wait(pid);
}


/* Creates a new file called file initially initial_size bytes in size.
 Returns true if successful, false otherwise.  */
static bool
create_handler(const char *file, unsigned initial_size)
{
	/* check invalid memory reference */
	/*if(!valid_pointer(&file) || !valid_pointer(&initial_size)){
		return false;
	}*/

	if(!valid_string(file))
	{
		exit_handler(-1);
		//return false;
	}
	bool success;
	//file = to_kernel_addr (file);

	lock_acquire (&fs_lock);
	success = filesys_create (file, initial_size);
	lock_release (&fs_lock);

	return success;
}


static bool
remove_handler(const char *file)
{	
	/* check invalid memory reference */
	/*if(!valid_pointer(&file)){
		return false;
	}*/

	// check for validity.
	if (!valid_string (file))
	{
		return false;
	}
	lock_acquire(&fs_lock);
	
	// remove it
	bool r_value = filesys_remove (file);
	
	lock_release(&fs_lock);

	return r_value;
}


static int
open_handler(const char* file)
{
	/* check invalid memory reference */
	/*if(!valid_pointer(&file)){
		return -1;
	}*/

	if (!valid_string (file))
	{
		return -1 ;	
	}

	lock_acquire(&fs_lock);

	struct file* open_file = filesys_open (file);

	lock_release(&fs_lock);

	if(open_file == NULL)
	{
			return -1 ;
	}

	// note that you should free the file_entry struct when close.
	struct file_entry* entry = malloc (sizeof (*entry));
	entry->fd = allocate_fd ();
	entry->file = open_file;
	list_push_back (&thread_current ()->open_file_table, &entry->hook);
	
	//printf("\nID %d\n", entry->fd);
	
	return entry->fd;
}

static void 
close_handler (int fd)
{

	struct file_entry *entry = get_file_entry_by_fd(fd);
	if(entry== NULL)
	{
		return;
	}
	list_remove(&entry->hook);
	file_close(entry->file);
	free(entry);
}


static int
read_handler(int fd, void *buffer, unsigned size)
{
	/* check invalid memory reference */
	/*if(!valid_pointer(&fd) || !valid_pointer(&buffer) || !valid_pointer(&size)){
		return -1;
	}*/
	if(!valid_pointer(buffer)){
		exit_handler(-1);
	}

	char* f_buffer = (char*) buffer;

	if(fd == 0){
		// read from keyboard
		int i = 0;
		for(;i<size;i++){
			f_buffer[i] = input_getc();
		}
		return size;
	}

	struct file_entry* entry = get_file_entry_by_fd(fd);
	if(entry == NULL){
		return -1;
	}

	struct file * current_file=entry->file;
	lock_acquire(&fs_lock);
	int r_value = file_read(current_file,buffer,size);
	lock_release(&fs_lock);

	return r_value;
}


static int
write_handler(int fd, void *buffer, unsigned size)
{
	/* check invalid memory reference */
	/*if(!valid_pointer(&fd) || !valid_pointer(&buffer) || !valid_pointer(&size)){
		return -1;
	}*/

	/* read from console */
	if (fd == 1) 
	{
		putbuf (buffer, size);
    	return size;
	}

	/* read from file */
	struct file_entry* entry = get_file_entry_by_fd(fd);
	if(entry == NULL){
		return -1;
	}



	struct file * f=entry->file;
	lock_acquire(&fs_lock);
	int len = file_write(f, buffer, size);
	lock_release(&fs_lock);
	return len;
}


/* Changes the next byte to be read or written in open file fd to position,
 expressed in bytes from the beginning of the file. */
static void 
seek_handler (int fd, unsigned position)
{
	/* check invalid memory reference */
	/*if(!valid_pointer(&fd) || !valid_pointer(&position)){
		return;
	}*/

 	struct file_entry* entry = get_file_entry_by_fd(fd);
	if(entry == NULL){
		return;
	}

	struct file * f=entry->file;
   	lock_acquire (&fs_lock);
  	file_seek (f, position);
  	lock_release (&fs_lock);
}


static unsigned
tell_handler(int fd)
{
	/* check invalid memory reference */
	/*if(!valid_pointer(&fd)){
		return 0;
	}*/

	struct file_entry* entry = get_file_entry_by_fd(fd);
	if(entry == NULL){
		return 0;
	}

	struct file * f=entry->file;
	lock_acquire(&fs_lock);
	int r_value = file_tell(f);
	lock_release(&fs_lock);
	return r_value;
}


/* Returns the size, in bytes, of the file open as fd. */
static int 
filesize_handler (int fd)
{
	/* check invalid memory reference */
	/*if(!valid_pointer(&fd)){
		return 0;
	}*/

 	struct file_entry* entry = get_file_entry_by_fd(fd);
	if(entry == NULL){
		return 0;
	}

	struct file * f=entry->file;
  	lock_acquire (&fs_lock);
  	int size = file_length (f);
  	lock_release (&fs_lock);
  	return size;
}






/* return file pointer crossponding to given fd. */
static struct file_entry *
get_file_entry_by_fd (int fd)
{
  struct list_elem *e;

  for (e = list_begin (&thread_current()->open_file_table);
  	   e != list_end (&thread_current()->open_file_table);
       e = list_next (e))
    {
      struct file_entry *entry = list_entry (e, struct file_entry, hook);
      if(entry->fd==fd){
      	return entry;
      }
    }
  return NULL;
}

static void 
signal_parent(int status)
{

  tid_t curr_tid = thread_current()->tid;
  struct list_elem *e;
  for (e = list_begin (&signal_list); e != list_end (&signal_list);
       e = list_next (e))
  	{
    	struct child_signal *sig = list_entry (e, struct child_signal, hook);
    	if(curr_tid == sig->child_tid)
    	{
      		sig->child_exit_status = status;
      		sig->finished = true;
      		break;
    	}
  	}
}


static int
allocate_fd()
{
	int fd = ++thread_current()->current_fd;
	return fd;
}

static bool
valid_string(char *str)
{
	if(str==NULL)
	{
		return false;
	}
	while(get_user((uint8_t*)str) != -1 && *str!='\0'){
		str++;
	}
	return *str=='\0';
}

static bool
valid_pointer (void* pt)
{
	if(pt==NULL)
	{
		return false;
	}

	uint8_t i=0;
	uint8_t bytes = 4;
	uint8_t* tmp = (uint8_t *)pt;
	for(; i<bytes; i++)
	{
		if(get_user((tmp+i)) == -1)
		{
			return false;
		}
	}


	return true;
}



/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
	if(is_kernel_vaddr(uaddr)){
		return -1;
	}

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


/* This function maps uaddr to kaddr. */
static bool
to_kernel_addr(void *uaddr)
{
	struct thread *curr = thread_current ();
	void *kaddr = NULL;
	if (is_user_vaddr(uaddr))
	{
		kaddr = pagedir_get_page (curr->pagedir, uaddr);
	} 
	/*if (kaddr == NULL)
	{
		// uaddr is unmapped
		exit_handler(-1);
	}*/
	return kaddr!=NULL;
}

static bool 
is_executable(char *file_name){
	while( *(file_name) != '\0'){
		if(*(file_name) == '.'){
			return false;
		}
		file_name++;
	}
	return true;
}