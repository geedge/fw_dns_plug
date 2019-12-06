#include <stdio.h>
#include <arpa/inet.h>

#include <MESA/stream.h>
#include <MESA/dns.h>
#include <MESA/cJSON.h>
#include <MESA_prof_load.h>
#include <MESA/Maat_rule.h>
#include <MESA/MESA_handle_logger.h>

#include "tsg_rule.h"
#include "tsg_send_log.h"
#include "fw_dns_plug.h"


char *g_fw_dns_conffile=(char *)"tsgconf/main.conf";
char FW_DNS_PLUG_VERSION_20191206=0;
struct _fw_dns_plug g_fw_dns_plug_info;

enum TSG_ETHOD_TYPE
{
	TSG_METHOD_TYPE_UNKNOWN=0,
	TSG_METHOD_TYPE_DROP,
	TSG_METHOD_TYPE_REDIRECTION,
	TSG_METHOD_TYPE_MAX
};

const struct _str2index method2index[TSG_METHOD_TYPE_MAX]={	{TSG_METHOD_TYPE_UNKNOWN, 7, (char *)"unknown"},
													{TSG_METHOD_TYPE_DROP, 4, (char *)"drop"},
													{TSG_METHOD_TYPE_REDIRECTION, 8, (char *)"redirect"}
	};

int tsg_get_method_id(char *method)
{
	int i=0;

	for(i=0; i<TSG_METHOD_TYPE_MAX; i++)
	{
		if(method2index[i].len==(int)strlen(method) && (strncasecmp(method2index[i].type, method, method2index[i].len))==0)
		{
			return method2index[i].index;
		}
	}

	return -1;
}

static int get_answer_ttl(cJSON *object)
{
	int min=0;
	int max=0;
	cJSON *item=NULL;

	item=cJSON_GetObjectItem(object, "min");
	min=item->valueint;

	item=cJSON_GetObjectItem(object, "max");
	max=item->valueint;

	return (rand()%(max-min+1)+min);
}

static cJSON * get_answer_records(cJSON *object, int qtype)
{
	int i=0;
	cJSON *item=NULL;
	int resolution_size=0;
	int answer_type=DNS_TYPE_UNKNOWN;
	
	cJSON *resolution_array=cJSON_GetObjectItem(object, "resolution");
	resolution_size=cJSON_GetArraySize(resolution_array);
	for(i=0; i<resolution_size; i++)
	{
		item=cJSON_GetArrayItem(resolution_array, i);
		cJSON *tmp=cJSON_GetObjectItem(item, "qtype");
		
		answer_type=fw_dns_type2index(tmp->valuestring);
		if(answer_type==qtype)
		{
			return cJSON_GetObjectItem(item, "answer");
		}
	}

	return NULL;
}

static char fw_dns_action(struct streaminfo *a_stream, dns_info_t *dns_info, Maat_rule_t *p_result, const void *a_packet)
{
	int record_id=0;
	int i=0,used_num=0;
	int answer_size=0,ret=0;
	int payload_len=0,ttl=0;
	dns_hdr_t *dns_hdr = NULL;
	cJSON *item=NULL;
	cJSON *a_item=NULL;
	cJSON *object=NULL;
	cJSON *answer_array=NULL;
	char *tmp_buff=NULL;
	unsigned char senddir=0;
	char state=PROT_STATE_GIVEME;
	int answer_type=DNS_TYPE_UNKNOWN;
	int method_type=TSG_METHOD_TYPE_UNKNOWN;
	cheat_pkt_opt_t cheat_opt[MAX_ANSWER_RECORDS_NUM];
	unsigned char cheat_pkt_payload[MAX_CHEAT_PKT_PAYLOAD_LEN];
	
	if(p_result->serv_def_len<128)
	{
		object=cJSON_Parse(p_result->service_defined);

		MESA_handle_runtime_log(g_fw_dns_plug_info.logger, 
								RLOG_LV_DEBUG,
								"DO_ACTION",
								"Hit policy_id: %d service: %d action: %d user_reagion: %s domain: %s qtype: %d addr: %s",
								p_result->config_id,
								p_result->service_id,
								p_result->action,
								p_result->service_defined,
								(char *)dns_info->query_question.qname,
								dns_info->query_question.qtype,
								printaddr(&a_stream->addr, a_stream->threadnum)
								);
	}
	else
	{
		tmp_buff=(char *)calloc(1, p_result->serv_def_len+1);
		Maat_read_rule(g_tsg_maat_feather, p_result, MAAT_RULE_SERV_DEFINE, tmp_buff, p_result->serv_def_len);
		object=cJSON_Parse(tmp_buff);

		MESA_handle_runtime_log(g_fw_dns_plug_info.logger, 
								RLOG_LV_DEBUG,
								"DO_ACTION",
								"Hit policy_id: %d service: %d action: %d user_reagion: %s domain: %s qtype: %d addr: %s",
								p_result->config_id,
								p_result->service_id,
								p_result->action,
								tmp_buff,
								(char *)dns_info->query_question.qname,
								dns_info->query_question.qtype,
								printaddr(&a_stream->addr, a_stream->threadnum)
								);
	}

	if(object==NULL)
	{
		MESA_handle_runtime_log(g_fw_dns_plug_info.logger, 
								RLOG_LV_FATAL,
								"DO_ACTION",
								"Hit policy_id: %d service: %d action: %d user_reagion: %s domain: %s qtype: %d addr: %s",
								p_result->config_id,
								p_result->service_id,
								p_result->action,
								(tmp_buff==NULL) ? p_result->service_defined : tmp_buff,
								(char *)dns_info->query_question.qname,
								dns_info->query_question.qtype,
								printaddr(&a_stream->addr, a_stream->threadnum)
								);

		if(tmp_buff!=NULL)
		{
			free(tmp_buff);
			tmp_buff=NULL;
		}
		
		return PROT_STATE_GIVEME;
	}
	
	item=cJSON_GetObjectItem(object, "method");
	if(item!=NULL)
	{
		method_type=tsg_get_method_id(item->valuestring);
	}
	
	switch(method_type)
	{
		case	TSG_METHOD_TYPE_DROP:
			state=PROT_STATE_DROPME|PROT_STATE_DROPPKT;
			break;
		case	TSG_METHOD_TYPE_REDIRECTION:
			answer_array=get_answer_records(object, dns_info->query_question.qtype);
			if(answer_array!=NULL)
			{
				memset(cheat_opt, 0, sizeof(cheat_opt));
				answer_size=cJSON_GetArraySize(answer_array);
				for(i=0; i<answer_size; i++)
				{
					item=cJSON_GetArrayItem(answer_array, i);
					a_item=cJSON_GetObjectItem(item, "atype");
					answer_type=fw_dns_type2index(a_item->valuestring);

					a_item=cJSON_GetObjectItem(item, "ttl");
					ttl=get_answer_ttl(a_item);
						
					a_item=cJSON_GetObjectItem(item, "value");
					if(a_item!=NULL)
					{
						cheat_opt[used_num].res_type=answer_type;
						cheat_opt[used_num].cfg_type=answer_type;
						cheat_opt[used_num].ttl=ttl;

						switch(answer_type)
						{
							case	DNS_TYPE_A:
								cheat_opt[used_num].res_len=sizeof(unsigned int);
								inet_pton(AF_INET, a_item->valuestring, (void *)cheat_opt[used_num].res_info);
								break;
							case	DNS_TYPE_AAAA:
								cheat_opt[used_num].res_len=IPV6_ADDR_LEN;
								inet_pton(AF_INET6, a_item->valuestring, (void *)cheat_opt[used_num].res_info);
								break;
							default:
								cheat_opt[used_num].res_len=(strlen(a_item->valuestring) > sizeof(cheat_opt[used_num].res_info)-1) ? sizeof(cheat_opt[used_num].res_info)-1 : strlen(a_item->valuestring);
								memcpy(cheat_opt[used_num].res_info, a_item->valuestring, cheat_opt[used_num].res_len);
								break;
						}
						used_num++;
					}
					else
					{
						a_item=cJSON_GetObjectItem(object, "record_id");
						record_id=a_item->valueint;

						a_item=cJSON_GetObjectItem(object, "selected_num");
						used_num+=get_cheat_opt(record_id, a_item->valueint, ttl, answer_type, cheat_opt+used_num, MAX_ANSWER_RECORDS_NUM-used_num);
					}
					
				}

				memset(cheat_pkt_payload, 0, MAX_CHEAT_PKT_PAYLOAD_LEN);

				dns_hdr = (dns_hdr_t *)cheat_pkt_payload;
				dns_hdr->id = dns_info->hdr_info.id;
				dns_hdr->qdcount = 1;
				dns_hdr->ancount = used_num;
				
				payload_len=build_cheat_pkt(cheat_pkt_payload, MAX_CHEAT_PKT_PAYLOAD_LEN, &dns_info->query_question, cheat_opt, used_num);
				if(payload_len==-1)
				{
					return -1;
				}

				senddir = MESA_dir_reverse(a_stream->routedir);
				ret=MESA_inject_pkt(a_stream, (const char *)cheat_pkt_payload, payload_len, (const char *)a_packet, senddir);
				if(ret<0)
				{
					MESA_handle_runtime_log(g_fw_dns_plug_info.logger,
												RLOG_LV_FATAL,
												"SEND_CHEAT_PKT",
												"Return of MESA_inject_pkt_feedback function is %d, qname: %s qtype: %d cfg_id: %d service: %d addr: %s",
												ret,
												dns_info->query_question.qname,
												dns_info->query_question.qtype,
												p_result->config_id,
												p_result->service_id,
												printaddr(&a_stream->addr, a_stream->threadnum)
												);
				}

				state=PROT_STATE_DROPME|PROT_STATE_DROPPKT;
			}
			else
			{
				MESA_handle_runtime_log(g_fw_dns_plug_info.logger, 
										RLOG_LV_FATAL,
										"DO_ACTION",
										"Hit policy_id: %d service: %d action: %d user_reagion: %s domain: %s qtype: %d addr: %s",
										p_result->config_id,
										p_result->service_id,
										p_result->action,
										(tmp_buff==NULL) ? p_result->service_defined : tmp_buff,
										(char *)dns_info->query_question.qname,
										dns_info->query_question.qtype,
										printaddr(&a_stream->addr, a_stream->threadnum)
									);
				state=PROT_STATE_GIVEME;
			}
			break;
		default:
			break;
	}
	
	cJSON_Delete(object);
	object=NULL;
	return state;
}

static int fw_dns_send_log(struct streaminfo *a_stream, dns_info_t *dns_info, struct Maat_rule_t *result, int result_num, int thread_seq)
{
	int i=0;
	dns_rr_t *rr=NULL;
	tsg_log_t log_msg;
	int cname_use_len=0,dns_sec=1;
	struct TLD_handle_t *handle=NULL;
	char cname[4096]={0},*rr_buf=NULL;
	int cname_size=sizeof(cname);
	
	handle=TLD_create(thread_seq);
	
	TLD_append(handle, (char *)"dns_qr", (void *)(long)dns_info->hdr_info.qr, TLD_TYPE_LONG);
	TLD_append(handle, (char *)"dns_aa", (void *)(long)dns_info->hdr_info.aa, TLD_TYPE_LONG);
	TLD_append(handle, (char *)"dns_message_id", (void *)(long)dns_info->hdr_info.id, TLD_TYPE_LONG);
	TLD_append(handle, (char *)"dns_opcode", (void *)(long)dns_info->hdr_info.opcode, TLD_TYPE_LONG);
	TLD_append(handle, (char *)"dns_ra", (void *)(long)dns_info->hdr_info.ra, TLD_TYPE_LONG);
	TLD_append(handle, (char *)"dns_rcode", (void *)(long)dns_info->hdr_info.rcode, TLD_TYPE_LONG);
	TLD_append(handle, (char *)"dns_rd", (void *)(long)dns_info->hdr_info.rd, TLD_TYPE_LONG);
	TLD_append(handle, (char *)"dns_tc", (void *)(long)dns_info->hdr_info.tc, TLD_TYPE_LONG);
	TLD_append(handle, (char *)"dns_qdcount", (void *)(long)dns_info->hdr_info.qdcount, TLD_TYPE_LONG);
	TLD_append(handle, (char *)"dns_ancount", (void *)(long)dns_info->hdr_info.ancount, TLD_TYPE_LONG);
	TLD_append(handle, (char *)"dns_nscount", (void *)(long)dns_info->hdr_info.aucount, TLD_TYPE_LONG);
	TLD_append(handle, (char *)"dns_arcount", (void *)(long)dns_info->hdr_info.adcount, TLD_TYPE_LONG);

	if((strlen((char *)dns_info->query_question.qname)) >0)
	{
		TLD_append(handle, (char *)"dns_qname", (void *)dns_info->query_question.qname, TLD_TYPE_STRING);		
		TLD_append(handle, (char *)"dns_qtype", (void *)(long)dns_info->query_question.qtype, TLD_TYPE_LONG);		
		TLD_append(handle, (char *)"dns_qclass", (void *)(long)dns_info->query_question.qclass, TLD_TYPE_LONG);
	}

	for(i=0; i<dns_info->rr_count && dns_info->rr != NULL; i++)
	{
		rr = &dns_info->rr[i];
		if(rr!=NULL && rr->type==DNS_TYPE_CNAME)
		{
			if(rr->rdata.cname != NULL && cname_size-cname_use_len > (int)strlen((const char *)rr->rdata.cname))
			{
				snprintf(cname+cname_use_len, cname_size-cname_use_len, "%s,", rr->rdata.cname);
				cname_use_len += strlen((const char *)rr->rdata.cname);
			}
		}
	}
	
	TLD_append(handle, (char *)"dns_cname", (void *)cname, TLD_TYPE_STRING);

	cJSON * object=cJSON_CreateObject();
	get_rr_str2json(object, dns_info, &dns_sec);
	rr_buf=cJSON_PrintUnformatted(object);
	TLD_append(handle, (char *)"dns_rr", (void *)rr_buf, TLD_TYPE_STRING);
	free(rr_buf);
	rr_buf=NULL;
	
	TLD_append(handle, (char *)"dns_sub", (void *)(long)dns_sec, TLD_TYPE_LONG);

	TLD_append(handle, (char *)"common_schema_type", (void *)"DNS", TLD_TYPE_STRING);

	log_msg.a_stream=a_stream;
	log_msg.result=result;
	log_msg.result_num=result_num;
	
	tsg_send_log(g_tsg_log_instance, handle, &log_msg, thread_seq);
	
	return 0;
}

extern "C" char FW_DNS_PLUG_ENTRY(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet)
{
	int ret=0,hit_num=0;
	scan_status_t mid=NULL;
	char state=PROT_STATE_GIVEME;
	struct Maat_rule_t result[MAX_RESULT_NUM], *p_result=NULL;
	dns_info_t *dns_info=(dns_info_t *)session_info->app_info;

	if(dns_info==NULL || strlen((char *)dns_info->query_question.qname)==0)
	{		
		MESA_handle_runtime_log(g_fw_dns_plug_info.logger, 
					RLOG_LV_FATAL,
					"DNS_PLUG",
					"Qname is %s, addr: %s",
					(dns_info==NULL) ? "NULL" : ((strlen((char *)dns_info->query_question.qname)==0) ? "NULL" : (char *)dns_info->query_question.qname),
					printaddr(&a_stream->addr, thread_seq)
					);
		return state;
	}
	
	ret=tsg_scan_nesting_addr(g_tsg_maat_feather, a_stream, PROTO_DNS, &mid, result, MAX_RESULT_NUM-hit_num);
	if(ret>0)
	{
		MESA_handle_runtime_log(g_fw_dns_plug_info.logger, 
								RLOG_LV_DEBUG,
								"SCAN_NEST_ADDR",
								"Hit policy_id: %d service: %d action: %d domain: %s qtype: %d addr: %s",								
								result[hit_num].config_id,
								result[hit_num].service_id,
								result[hit_num].action,
								(char *)dns_info->query_question.qname,
								dns_info->query_question.qtype,
								printaddr(&a_stream->addr, thread_seq)
								);
		hit_num+=ret;
	}
	else
	{
		MESA_handle_runtime_log(g_fw_dns_plug_info.logger, 
								RLOG_LV_DEBUG,
								"SCAN_NEST_ADDR",
								"Scan domain: %s qtype: %d ret: %d addr: %s",
								(char *)dns_info->query_question.qname,
								dns_info->query_question.qtype,
								ret,
								printaddr(&a_stream->addr, thread_seq)
								);
								
	}
	
	ret=Maat_full_scan_string(g_tsg_maat_feather,
							g_fw_dns_plug_info.table_qname_id,
							CHARSET_UTF8,
							(char *)dns_info->query_question.qname,
							strlen((char *)dns_info->query_question.qname),
							result+hit_num, 
							NULL,
							MAX_RESULT_NUM-hit_num,
							&mid,
							thread_seq);

	if(ret>0)
	{
		MESA_handle_runtime_log(g_fw_dns_plug_info.logger, 
								RLOG_LV_DEBUG,
								"SCAN_DOMAIN",
								"Hit domain: %s qtype: %d policy_id: %d service: %d action: %d addr: %s",
								(char *)dns_info->query_question.qname,
								dns_info->query_question.qtype,
								result[hit_num].config_id,
								result[hit_num].service_id,
								result[hit_num].action,
								printaddr(&a_stream->addr, thread_seq)
								);
		hit_num+=ret;
	}
	else
	{
		MESA_handle_runtime_log(g_fw_dns_plug_info.logger, 
								RLOG_LV_DEBUG,
								"SCAN_DOMAIN",
								"Scan domain: %s qtype: %d ret: %d addr: %s",
								(char *)dns_info->query_question.qname,
								dns_info->query_question.qtype,
								ret,
								printaddr(&a_stream->addr, thread_seq)
								);
								
	}

	if(hit_num>0)
	{
		p_result=tsg_fetch_deny_rule(result, hit_num);
		
		if(p_result!=NULL)
		{
			state=fw_dns_action(a_stream, dns_info, p_result, a_packet);
			hit_num=1;
		}

		fw_dns_send_log(a_stream, dns_info, result, hit_num, thread_seq);
	}


	return state;
}

extern "C" int FW_DNS_PLUG_INIT(void)
{
	int level=30,ret=0;
	char log_path[256]={0};
	memset(&g_fw_dns_plug_info, 0, sizeof(g_fw_dns_plug_info));

	MESA_load_profile_int_def(g_fw_dns_conffile, "DNS_PLUG", "LOG_LEVEL", &level, 30);
	MESA_load_profile_string_def(g_fw_dns_conffile, "DNS_PLUG", "LOG_PATH", log_path, sizeof(log_path), "tsglog/fw_dns_plug/fw_dns_plug");


	MESA_load_profile_string_def(g_fw_dns_conffile, "DNS_PLUG", "TABLE_QNAME", g_fw_dns_plug_info.table_qname, MAX_TABLE_NAME_LEN, "TSG_FIELD_DNS_QNAME");

	g_fw_dns_plug_info.logger=MESA_create_runtime_log_handle(log_path, level);
	if(g_fw_dns_plug_info.logger==NULL)
	{
		printf("MESA_create_runtime_log_handle failed, log_path: %s level: %d", (log_path==NULL) ? NULL : log_path, level);
		return -1;
	}

	g_fw_dns_plug_info.table_qname_id=Maat_table_register(g_tsg_maat_feather, g_fw_dns_plug_info.table_qname);
	if(g_fw_dns_plug_info.table_qname_id<0)
	{
		MESA_handle_runtime_log(g_fw_dns_plug_info.logger, RLOG_LV_FATAL, "REGISTER_TABLE", "Maat_table_register failed, table_name: %s", g_fw_dns_plug_info.table_qname);
		return -1;
	}

	ret=fw_dns_rule_init(g_fw_dns_conffile, g_fw_dns_plug_info.logger);
	if(ret<0)
	{
		return -1;
	}
	
	return 0;
}


extern "C" void FW_DNS_PLUG_DESTORY(void)
{
	return ;
}

