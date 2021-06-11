#ifndef	__FW_DNS_RULE_H__
#define	__FW_DNS_RULE_H__

#if(__GNUC__ * 100 + __GNUC_MINOR__ * 10 + __GNUC_PATCHLEVEL__ >= 411)
#define atomic_inc(x) __sync_add_and_fetch((x),1)
#define atomic_dec(x) __sync_sub_and_fetch((x),1)
#define atomic_add(x,y) __sync_add_and_fetch((x),(y))
#define atomic_sub(x,y) __sync_sub_and_fetch((x),(y))
typedef int atomic_t;
#define ATOMIC_INIT(i)  { (i) }
#define atomic_read(x) __sync_add_and_fetch((x),0)
#define atomic_set(x,y) __sync_lock_test_and_set((x),y)
#else 
#include <alsa/iatomic.h>
#endif 

#define	MIN(a, b) ((a>b) ? b: a)

#define	MAX_TABLE_NAME_LEN	32

struct dns_str2idx
{
	int index;
	int len;
	char *type;
};

struct dns_records
{
	int ref_cnt;
	int record_id;
	int record_num;
	int is_valid;
	int table_id;
	char record_type[128];
	char record_name[MAX_TABLE_NAME_LEN];
	void **record_values;
};

struct fw_dns_rule
{
	int table_records_id;
	char table_records_name[MAX_TABLE_NAME_LEN];
};


int fw_dns_type2index(char *type);
int fw_dns_rule_init(const char *conffile, void *logger);
int dns_get_cheat_opt(int record_id, int select_num, int ttl, int atype, cheat_pkt_opt_t* cheat_opt, int cheat_opt_num);
	
#endif
