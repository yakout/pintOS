#ifndef FIXED_POINT_H_
#define FIXED_POINT_H_

/*
	Convert n to fixed point:	n * f
	Convert x to integer (rounding toward zero):	x / f
	Convert x to integer (rounding to nearest):	(x + f / 2) / f if x >= 0, 
	(x - f / 2) / f if x <= 0.
	Add x and y:	x + y
	Subtract y from x:	x - y
	Add x and n:	x + n * f
	Subtract n from x:	x - n * f
	Multiply x by y:	((int64_t) x) * y / f
	Multiply x by n:	x * n
	Divide x by y:	((int64_t) x) * f / y
	Divide x by n:	x / n
	*/

struct fixed_point{
	int value
}


struct fixed_point int_to_fixedpoint(int number);
int fixedpoint_to_int(struct fixed_point number);

struct fixed_point fixedpoint_add(struct fixed_point number1, struct fixed_point number2);
struct fixed_point fixedpoint_subtract(struct fixed_point number1, struct fixed_point number2);
struct fixed_point fixedpoint_multiply(struct fixed_point number1, struct fixed_point number2);
struct fixed_point fixedpoint_divide(struct fixed_point number1, struct fixed_point number2);


//struct fixed_point calculate_load_avg(struct fixed_point load_avg, int ready_threads);



#endif /* lib/fixed_point.h*/
















