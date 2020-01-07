#include <stdio.h>
#include <arpa/inet.h>

#include <MESA/stream.h>
#include <MESA/dns.h>
#include <MESA/cJSON.h>

#include <MESA_prof_load.h>
#include <MESA/Maat_rule.h>
#include <MESA/MESA_handle_logger.h>

#include "tsg_rule.h"
#include "fw_dns_rule.h"

fw_dns_rule_t g_fw_dns_rule_info;
char FW_DNS_RULE_VERSION_20191201=0;

struct _dns_str2idx str2index[]={{DNS_TYPE_CNAME,	5, (char *)"CNAME"},
								{DNS_TYPE_MX,	2, (char *)"MX"},
								{DNS_TYPE_A, 	1, (char *)"A"},
								{DNS_TYPE_NS,	2, (char *)"NS"},
								{DNS_TYPE_AAAA,	4, (char *)"AAAA"},
								{DNS_TYPE_TXT,	3, (char *)"TXT"},
								{DNS_TYPE_PTR,	3, (char *)"PTR"}
								};

int fw_dns_type2index(char *type)
{
	int i=0;
	
	for(i=0; i<(int)(sizeof(str2index)/sizeof(struct _dns_str2idx)); i++)
	{
		if(str2index[i].len==(int)strlen(type) && (strncasecmp(str2index[i].type, type, str2index[i].len))==0)
		{
			return str2index[i].index;
		}
	}

	return -1;
}

int get_cheat_opt(int record_id, int select_num, int ttl, int atype, cheat_pkt_opt_t* cheat_opt, int cheat_opt_num)
{
	int i=0,idx=0;
	int used_num=0,real_num=0;
	cb_rule_t *cb_rule=NULL;
	
	real_num=(select_num>cheat_opt_num) ? cheat_opt_num : select_num;
	
	cb_rule=(cb_rule_t *)Maat_plugin_get_EX_data(g_tsg_maat_feather, g_fw_dns_rule_info.table_records_id, (char *)&record_id);
	if(cb_rule!=NULL && real_num>0)
	{
		idx = (cb_rule->record_num>=real_num) ? (random()%(cb_rule->record_num-real_num+1)) : 0;
		for(i=0; i<real_num && i+idx<cb_rule->record_num; i++)
		{
			cheat_opt[used_num].ttl=ttl;
			cheat_opt[used_num].res_type=atype;
			cheat_opt[used_num].cfg_type=atype;
			switch(atype)
			{
				case	DNS_TYPE_A:
					cheat_opt[used_num].res_len=sizeof(unsigned int);
					break;
				case	DNS_TYPE_AAAA:
					cheat_opt[used_num].res_len=IPV6_ADDR_LEN;
					break;
				default:					
					cheat_opt[used_num].res_len=MIN(strlen((char *)(cb_rule->record_values[i+idx])), sizeof(cheat_opt[used_num].res_info)-1);
					break;
			}
			
			memcpy(cheat_opt[used_num].res_info, (char *)(cb_rule->record_values[i+idx]), cheat_opt[used_num].res_len);
			used_num++;
		}
	}
	
	return used_num;
}


void fw_dns_EX_data_create(int table_id, const char* key, const char* table_line, MAAT_PLUGIN_EX_DATA* ad, long argl, void *argp)
{
	int i=0;
	cJSON *pSub=NULL;
	cb_rule_t *cb_rule=(cb_rule_t *)calloc(1, sizeof(cb_rule_t));
	char *tmp_records=(char *)calloc(1, strlen(table_line)+1);
		
	sscanf(table_line, "%d	%s	%s	%s	%d", &cb_rule->record_id, cb_rule->record_name, cb_rule->record_type, tmp_records, &cb_rule->is_valid);

	int index=fw_dns_type2index(cb_rule->record_type);

	cJSON *tmp_array=cJSON_Parse(tmp_records);	
	if(tmp_array != NULL)
	{
		cb_rule->record_num=cJSON_GetArraySize(tmp_array);
		*cb_rule->record_values=(void *)malloc(cb_rule->record_num*sizeof(void *));
		
		for(i=0; i<cb_rule->record_num; i++)
		{
			pSub = cJSON_GetArrayItem(tmp_array, i);
			if(NULL==pSub )
			{
				continue; 
			}

			switch(index)
			{
				case	DNS_TYPE_A:
					cb_rule->record_values[i]=calloc(1, sizeof(unsigned int));
					inet_pton(AF_INET, pSub->valuestring, cb_rule->record_values[i]);
					break;
				case	DNS_TYPE_AAAA:
					cb_rule->record_values[i]=calloc(1, IPV6_ADDR_LEN);
					inet_pton(AF_INET6, pSub->valuestring, cb_rule->record_values[i]);
					break;
				case	DNS_TYPE_MX:
					break;
				case	DNS_TYPE_NS:
				case	DNS_TYPE_TXT:
				case	DNS_TYPE_PTR:
				case	DNS_TYPE_CNAME:
					cb_rule->record_values[i]=calloc(1, strlen(pSub->valuestring)+1);
					memcpy(cb_rule->record_values[i], pSub->valuestring, strlen(pSub->valuestring));
					break;
				default:
					continue;	
			}
		}
	}

	free(tmp_records);
}

void fw_dns_EX_data_free(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void *argp)
{
	int i=0;
	cb_rule_t *cb_rule=(cb_rule_t *)*ad;
	
	if(cb_rule!=NULL)
	{
		for(i=0; i<cb_rule->record_num; i++)
		{
			free(cb_rule->record_values[i]);
			cb_rule->record_values[i]=NULL;
		}
		free(*cb_rule->record_values);
		*cb_rule->record_values=NULL;

		free(cb_rule);
		cb_rule=NULL;
	}
}
void fw_dns_EX_data_dup(int table_id, MAAT_PLUGIN_EX_DATA *to, MAAT_PLUGIN_EX_DATA *from, long argl, void *argp)
{
	
}

int fw_dns_EX_data_key2index(const char* key)
{
	return 0;
}


int fw_dns_rule_init(const char *conffile, void *logger)
{
	int ret=0;
	long arg=0;
	memset(&g_fw_dns_rule_info, 0, sizeof(g_fw_dns_rule_info));
	
	MESA_load_profile_string_def(conffile, "DNS_PLUG", "TABLE_RECORDS", g_fw_dns_rule_info.table_records_name, MAX_TABLE_NAME_LEN, (char *)"FW_PROFILE_DNS_RECORDS");

	g_fw_dns_rule_info.table_records_id=Maat_table_register(g_tsg_maat_feather, g_fw_dns_rule_info.table_records_name);
	if(g_fw_dns_rule_info.table_records_id<0)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "REGISTER_TABLE", "Maat_table_register failed, table_name: %s", g_fw_dns_rule_info.table_records_name);
		return -1;
	}

	ret=Maat_plugin_EX_register(g_tsg_maat_feather,
								g_fw_dns_rule_info.table_records_id,
								fw_dns_EX_data_create,
								fw_dns_EX_data_free,
								fw_dns_EX_data_dup,
								fw_dns_EX_data_key2index,
								arg, 
								NULL);

	if(ret<0)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "REGISTER_TABLE", "Maat_plugin_EX_register failed, table_name: %s", g_fw_dns_rule_info.table_records_name);
		return -1;
	}

	return 0;
}

