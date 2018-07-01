/* SPDX-License-Identifier: GPL-2.0 */

#ifndef atomic_try_cmpxchg

#define __atomic_try_cmpxchg(type, _p, _po, _n)				\
({									\
	typeof(_po) __po = (_po);					\
	typeof(*(_po)) __o = *__po;					\
	*__po = atomic_cmpxchg##type((_p), __o, (_n));			\
	(*__po == __o);							\
})

#define atomic_try_cmpxchg(_p, _po, _n)		__atomic_try_cmpxchg(, _p, _po, _n)
#define atomic_try_cmpxchg_relaxed(_p, _po, _n)	__atomic_try_cmpxchg(_relaxed, _p, _po, _n)
#define atomic_try_cmpxchg_acquire(_p, _po, _n)	__atomic_try_cmpxchg(_acquire, _p, _po, _n)
#define atomic_try_cmpxchg_release(_p, _po, _n)	__atomic_try_cmpxchg(_release, _p, _po, _n)

#else /* atomic_try_cmpxchg */
#define atomic_try_cmpxchg_relaxed	atomic_try_cmpxchg
#define atomic_try_cmpxchg_acquire	atomic_try_cmpxchg
#define atomic_try_cmpxchg_release	atomic_try_cmpxchg
#endif /* atomic_try_cmpxchg */
