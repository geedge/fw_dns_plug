#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>

#include <MESA/stream.h>
#include <MESA/dns.h>
#include <MESA/cJSON.h>

#include <MESA_prof_load.h>
#include <MESA/Maat_rule.h>
#include <MESA/MESA_handle_logger.h>

#include "tsg_rule.h"
#include "fw_dns_rule.h"

struct fw_dns_rule g_fw_dns_rule_info;
char FW_DNS_RULE_VERSION_20191201=0;

struct dns_str2idx str2index[]={{DNS_TYPE_CNAME,	5, (char *)"CNAME"},
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
	
	for(i=0; i<(int)(sizeof(str2index)/sizeof(struct dns_str2idx)); i++)
	{
		if(str2index[i].len==(int)strlen(type) && (strncasecmp(str2index[i].type, type, str2index[i].len))==0)
		{
			return str2index[i].index;
		}
	}

	return -1;
}

void fw_dns_EX_data_create(int table_id, const char* key, const char* table_line, MAAT_PLUGIN_EX_DATA* ad, long argl, void *argp)
{
	int i=0;
	cJSON *one_record=NULL,*pSub=NULL;

	struct dns_records *records=(struct dns_records *)calloc(1, sizeof(struct dns_records));
	char *tmp_records=(char *)calloc(1, strlen(table_line)+1);		
	sscanf(table_line, "%d	%s	%s	%s	%d", &records->record_id, records->record_name, records->record_type, tmp_records, &records->is_valid);

	int index=fw_dns_type2index(records->record_type);
	cJSON *tmp_array=cJSON_Parse(tmp_records);	
	if(tmp_array!=NULL)
	{
		records->record_num=cJSON_GetArraySize(tmp_array);
		records->record_values=(void **)malloc(records->record_num*sizeof(void *));
		
		for(i=0; i<records->record_num; i++)
		{
			one_record=cJSON_GetArrayItem(tmp_array, i);
			if(one_record==NULL)
			{
				continue;
			}
			
			pSub=cJSON_GetObjectItem(one_record, "value");
			if(NULL==pSub )
			{
				continue; 
			}

			switch(index)
			{
				case	DNS_TYPE_A:
					records->record_values[i]=calloc(1, sizeof(unsigned int));
					inet_pton(AF_INET, pSub->valuestring, records->record_values[i]);
					break;
				case	DNS_TYPE_AAAA:
					records->record_values[i]=calloc(1, IPV6_ADDR_LEN);
					inet_pton(AF_INET6, pSub->valuestring, records->record_values[i]);
					break;
				case	DNS_TYPE_MX:
					break;
				case	DNS_TYPE_NS:
				case	DNS_TYPE_TXT:
				case	DNS_TYPE_PTR:
				case	DNS_TYPE_CNAME:
					records->record_values[i]=calloc(1, strlen(pSub->valuestring)+1);
					memcpy(records->record_values[i], pSub->valuestring, strlen(pSub->valuestring));
					break;
				default:
					continue;	
			}
		}

		records->table_id=table_id;
		atomic_inc(&records->ref_cnt);
		(*ad)=(MAAT_PLUGIN_EX_DATA)(records);

		cJSON_Delete(tmp_array);
		tmp_array=NULL;
	}
	else
	{
		free(records);
		records=NULL;
	}

	free(tmp_records);
	tmp_records=NULL;

	return ;
}

void fw_dns_EX_data_free(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void *argp)
{
	int i=0;
	struct dns_records *records=(struct dns_records *)*ad;
	
	if(records!=NULL)
	{
		atomic_dec(&records->ref_cnt);
		if(records->ref_cnt<=0)
		{
			for(i=0; i<records->record_num; i++)
			{
				free(records->record_values[i]);
				records->record_values[i]=NULL;
			}
			
			free(*records->record_values);
			*records->record_values=NULL;

			free(records);
			records=NULL;
		}
	}

	return ;
}

void fw_dns_EX_data_dup(int table_id, MAAT_PLUGIN_EX_DATA *to, MAAT_PLUGIN_EX_DATA *from, long argl, void *argp)
{
	struct dns_records *records=(struct dns_records *)(*from);

	if(records!=NULL)
	{
		atomic_inc(&records->ref_cnt);
		(*to)=(*from);
	}

	return ;
}

static int set_one_cheat_opt(cheat_pkt_opt_t *cheat_opt, int ttl, int atype, char *record_values)
{
	cheat_opt->ttl=ttl;
	cheat_opt->res_type=atype;
	cheat_opt->cfg_type=atype;
	
	switch(atype)
	{
		case	DNS_TYPE_A:
			cheat_opt->res_len=sizeof(unsigned int);
			break;
		case	DNS_TYPE_AAAA:
			cheat_opt->res_len=IPV6_ADDR_LEN;
			break;
		case	DNS_TYPE_NS:
		case	DNS_TYPE_TXT:
		case	DNS_TYPE_PTR:
		case	DNS_TYPE_CNAME: 				
			cheat_opt->res_len=MIN(strlen(record_values), sizeof(cheat_opt->res_info)-1);
			break;
		default:					
			return 0;
	}
	
	memcpy(cheat_opt->res_info, record_values, cheat_opt->res_len);
	
	return 1;

}

int dns_get_cheat_opt(int record_id, int select_num, int ttl, int atype, cheat_pkt_opt_t* cheat_opt, int cheat_opt_num)
{
	int i=0,idx=0;
	char record_id_str[32]={0};
	int used_num=0,real_num=0;
	struct dns_records *records=NULL;
	
	real_num=MIN(select_num, cheat_opt_num);
	if(real_num<=0)
	{
		return 0;
	}
	
	snprintf(record_id_str, sizeof(record_id_str), "%d", record_id);
	records=(struct dns_records *)Maat_plugin_get_EX_data(g_tsg_maat_feather, g_fw_dns_rule_info.table_records_id, record_id_str);
	if(records!=NULL)
	{ 
		if(records->record_num<=real_num)
		{
			for(i=0; i<records->record_num; i++)
			{
				used_num+=set_one_cheat_opt(&(cheat_opt[used_num]), ttl, atype, (char *)(records->record_values[i]));
			}
		}
		else
		{
			srand(time(0));
			idx=rand()%(records->record_num-real_num+1);
			for(i=0; i<real_num; i++)
			{
				used_num+=set_one_cheat_opt(&(cheat_opt[used_num]), ttl, atype, (char *)(records->record_values[idx+i]));
			}
		}

		fw_dns_EX_data_free(records->table_id, (MAAT_PLUGIN_EX_DATA *)&records, 0, NULL);
	}
	
	return used_num;
}


int fw_dns_rule_init(const char *conffile, void *logger)
{
	int ret=0;
	long arg=0;
	memset(&g_fw_dns_rule_info, 0, sizeof(g_fw_dns_rule_info));
	
	MESA_load_profile_string_def(conffile, "DNS_PLUG", "TABLE_RECORDS", g_fw_dns_rule_info.table_records_name, MAX_TABLE_NAME_LEN, (char *)"TSG_PROFILE_DNS_RECORDS");

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
								NULL,
								arg, 
								NULL);

	if(ret<0)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "REGISTER_TABLE", "Maat_plugin_EX_register failed, table_name: %s", g_fw_dns_rule_info.table_records_name);
		return -1;
	}

	return 0;
}

