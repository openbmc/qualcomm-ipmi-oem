#include "oemhandler.hpp"
#include <host-ipmid/ipmid-api.h>
#include <fstream>
#include <stdio.h>
#include <string.h>
#include <systemd/sd-bus.h>
#include <endian.h>

void register_netfn_none() __attribute__((constructor));
void register_netfn_qdt_oem() __attribute__((constructor));

#define EXPORTGPIO "/sys/class/gpio/export"
#define M2_EEPROM_PATH "/sys/class/i2c-dev/i2c-16/device/16-0052/eeprom"
#define PCIE_SLOT_1_EEPROM_PATH "/sys/class/i2c-dev/i2c-18/device/18-0057/eeprom"
#define PCIE_SLOT_2_EEPROM_PATH "/sys/class/i2c-dev/i2c-23/device/23-0057/eeprom"
#define SOC_MAC_PATH "/tmp/soc_mac"
#define PLATFORM_MAC_PATH "/tmp/platform_mac"
#define GPIOG1FIlE "/sys/class/gpio/gpio329/value"
#define GPIOP4FIlE "/sys/class/gpio/gpio404/value"
#define GPIOP5FIlE "/sys/class/gpio/gpio405/value"
#define GPIOP6FIlE "/sys/class/gpio/gpio406/value"

#define NODE0HW1PWM "/sys/class/hwmon/hwmon1/pwm1"
#define NODE0HW2PWM "/sys/class/hwmon/hwmon2/pwm1"
#define NODE1HW1PWM "/sys/class/hwmon/hwmon1/pwm3"
#define NODE1HW2PWM "/sys/class/hwmon/hwmon2/pwm3"

ipmi_ret_t ipmi_arm_oem_get_pcie_slot_status(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                     ipmi_request_t request, ipmi_response_t response,
                                     ipmi_data_len_t data_len, ipmi_context_t context)
{
    FILE *fp;
    char *type_info;
    uint8_t *reqptr = (uint8_t *) request;
    char respptr[1];
    *data_len = 2;
    ipmi_ret_t ipmi_rc = IPMI_CC_OK;
    type_info = (char*) malloc (sizeof(char*)*4);
    if (reqptr[0] == 0)
    {
        fp = fopen(PCIE_SLOT_1_EEPROM_PATH,"r");
        if(fp == NULL) {
            printf("fail to open file");
            respptr[0] = 0xff;
        } else {
            fseek(fp, 39, SEEK_SET);
            fread(type_info,1,4,fp);
            switch(type_info[3]) {
                case '0':
                    fp = fopen(M2_EEPROM_PATH,"r");
                    if(fp == NULL) {
                         printf("fail to open file");
                         respptr[0] = 0x01;
                    } else {
                         respptr[0] = 0xFA;
                    }
                    break;
                case '1':
                    respptr[0] = 0x02;
                break;
                case '2':
                    respptr[0] = 0x03;
                break;
                case '3':
                    respptr[0] = 0x04;
                break;
                case '4':
                    respptr[0] = 0x05;
                break;
                case '6':
                    respptr[0] = 0x06;
                break;
                case '7':
                    respptr[0] = 0x07;
                break;
                default:
                    respptr[0] = 0xff;
             }
        }
    } else if (reqptr[0] == 1) {
        fp = fopen(PCIE_SLOT_2_EEPROM_PATH,"r");
        if(fp == NULL) {
            printf("fail to open file\n");
            respptr[0] = 0xff;
        } else {
            fseek(fp, 39, SEEK_SET);
            fread(type_info,1,4,fp);
            switch(type_info[3]) {
                case '0':
                    respptr[0] = 0x01;
                break;
                case '1':
                    respptr[0] = 0x02;
                break;
                case '2':
                    respptr[0] = 0x03;
                break;
                case '3':
                    respptr[0] = 0x04;
                break;
                case '4':
                    respptr[0] = 0x05;
                break;
                case '6':
                    respptr[0] = 0x06;
                break;
                case '7':
                    respptr[0] = 0x07;
                break;
                default:
                    respptr[0] = 0xff;
            }
        }
    } else {
        ipmi_rc = IPMI_CC_PARM_OUT_OF_RANGE;
    }
    memcpy(response, respptr, *data_len);
    return ipmi_rc;
}

ipmi_ret_t ipmi_arm_oem_get_bmc_vendor(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    uint8_t *reqptr = (uint8_t *) request;
    ipmi_ret_t rc = IPMI_CC_OK;
    char respptr[3];

    if((reqptr[0] == 0xA9) &&
         (reqptr[1] == 0x05) &&
          (reqptr[2] == 0x00))
    {
        *data_len = 4;
        respptr[0] = 'B';
        respptr[1] = 'M';
        respptr[2] = 'C';
    } else {
        rc = IPMI_CC_INVALID_FIELD_REQUEST;
        respptr[0] = 0x00;
        *data_len = 1;
    }
    memcpy(response, respptr, *data_len);
    return rc;
}
ipmi_ret_t ipmi_arm_oem_get_node_id_detection(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{

    FILE *fp;
    char config[8] = {0};
    int cnt = 0;
    char respptr[1];
    *data_len = 2;
    ipmi_ret_t ipmi_rc = IPMI_CC_OK;

    fp = fopen(GPIOG1FIlE, "r");
    if (fp == NULL) {
            respptr[0] = 0x00;
    }

    fgets(config,8,fp);
    cnt += atoi(config);
    fclose(fp);

    if (cnt == 0) {
           respptr[0] = 0x00;
    } else {
           respptr[0] = 0x01;
    }

    memcpy(response, respptr, *data_len);
    return ipmi_rc;
}

ipmi_ret_t ipmi_arm_oem_get_broad_id_detection(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    FILE *fp1;
    FILE *fp2;
    FILE *fp3;
    char config[8] = {0};
    int cnt = 0;
    char respptr[1];
    *data_len = 2;
    ipmi_ret_t ipmi_rc = IPMI_CC_OK;
    fp1 = fopen(GPIOP4FIlE, "r");
    if (fp1 == NULL) {
        cnt += 0xf;
    }
    else{
        memset(config, 0, sizeof(config)),
        fgets(config,8,fp1);
        cnt += atoi(config);
    }
    fclose(fp1);
    fp2 = fopen(GPIOP5FIlE, "r");
    if (fp2 == NULL) {
        cnt += 0xf;
    }
    else{
        memset(config, 0, sizeof(config)),
        fgets(config,8,fp2);
        cnt += atoi(config);
    }
    fclose(fp2);
    fp3 = fopen(GPIOP6FIlE, "r");
    if (fp3 == NULL) {
        cnt += 0xf;
    }
    else{
        memset(config, 0, sizeof(config)),
        fgets(config,8,fp3);
        cnt += atoi(config);
    }
    fclose(fp3);

    if(cnt == 0)
        respptr[0] = 0x00;
    else if (cnt == 1)
        respptr[0] = 0x01;
    else if (cnt == 2)
        respptr[0] = 0x02;
    else
        respptr[0] = 0xff;

    memcpy(response, respptr, *data_len);
    return ipmi_rc;

}

ipmi_ret_t ipmi_arm_oem_send_soc_mac(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    FILE *fp;
    uint8_t *reqptr = (uint8_t *) request;
    *data_len = 2;
    ipmi_ret_t ipmi_rc = IPMI_CC_OK;
    char buffer[40];
    int i;
    int c = 0;

    for(i=0; i < 12; i++)
    {
         if(( i == 5)||(i == 11))
         {
             sprintf(buffer+(c),"%x\n",reqptr[i]);
             c = c + 5;
         }
         else{
             sprintf(buffer+(c),"%x:",reqptr[i]);
             c = c + 3;
         }
    }
    if ((fp = fopen(SOC_MAC_PATH, "w")) != NULL)
    {
        fwrite(buffer, sizeof(char), c, fp);
        fclose(fp);
    }

    return ipmi_rc;
}

ipmi_ret_t ipmi_arm_oem_send_platform_mac(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    FILE *fp;
    uint8_t *reqptr = (uint8_t *) request;
    *data_len = 2;
    ipmi_ret_t ipmi_rc = IPMI_CC_OK;
    char buffer[40];
    int i;
    int c = 0;

    for(i=0; i < 18; i++)
    {
         if(( i == 5)||(i == 11)||(i == 17))
         {
             sprintf(buffer+(c),"%x\n",reqptr[i]);
             c = c + 5;
         }
         else{
             sprintf(buffer+(c),"%x:",reqptr[i]);
             c = c + 3;
         }
    }
    if ((fp = fopen(PLATFORM_MAC_PATH, "w")) != NULL)
    {
        fwrite(buffer, sizeof(char), c, fp);
        fclose(fp);
    }

    return ipmi_rc;
}

ipmi_ret_t ipmi_qdt_oem_set_boot_mode(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
	uint8_t *reqptr = (uint8_t *) request;
	ipmi_ret_t ipmi_rc = IPMI_CC_OK;
	int rc = 0;
	char command[50];
	char res[4];
	if(*data_len != 6)
	{
		return IPMI_CC_REQ_DATA_LEN_INVALID;
	}
	if( (reqptr[0] != 0xa9) || (reqptr[1] != 0x05) || (reqptr[2] != 0x00) )
	{
		return IPMI_CC_PARM_OUT_OF_RANGE;
	}
	sprintf(command,"/usr/bin/bootmodeutil -w %x %x %x %x %x %x",reqptr[0],reqptr[1],reqptr[2],reqptr[3],reqptr[4],reqptr[5]);
	rc=system(command);
	rc = WEXITSTATUS(rc);
	if (rc != 0) {
		return IPMI_CC_UNSPECIFIED_ERROR;
	}
	res[0]=reqptr[0];
	res[1]=reqptr[1];
	res[2]=reqptr[2];
	memcpy(response, res, sizeof(res));
	*data_len=3;
	return ipmi_rc;
}

ipmi_ret_t ipmi_qdt_oem_get_boot_mode(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
        FILE *fp;
        uint8_t *reqptr = (uint8_t *) request;
        ipmi_ret_t ipmi_rc = IPMI_CC_OK;
	char buff[5];
        char res[8];
        if(*data_len != 3)
        {
                return IPMI_CC_REQ_DATA_LEN_INVALID;
        }
        if( (reqptr[0] != 0xa9) || (reqptr[1] != 0x05) || (reqptr[2] != 0x00) )
        {
                return IPMI_CC_PARM_OUT_OF_RANGE;
        }
	res[0]=reqptr[0];
	res[1]=reqptr[1];
	res[2]=reqptr[2];
	int i;
        fp = fopen("/usr/bin/BOOTMODEFILE", "r");
	if(fp!= NULL)
	{
		for(i = 3; i < 6; i++)
		{
			fscanf(fp, "%s", buff);
			res[i]=strtol(buff,NULL,16);
		}
		memcpy(response, res, sizeof(res));
		*data_len=6;
	}else {
		printf("can not open the file\n");
		return 0xC3;
	}
	felose(fp);
	return ipmi_rc;
}

ipmi_ret_t ipmi_arm_oem_set_fan_speed(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
        FILE *fp;
        uint8_t *reqptr = (uint8_t *) request;
        ipmi_ret_t ipmi_rc = IPMI_CC_OK;
        int value=0;
	int node_num=0;
	char buff[5];
	uint8_t buff1;
        if(*data_len != 2)
        {
                return IPMI_CC_REQ_DATA_LEN_INVALID;
        }
	fp = fopen(GPIOG1FIlE, "r");
        if(fp != NULL)
        {
                fscanf(fp, "%s", buff);
                node_num=strtol(buff,NULL,10);
        }
        else
        {
                printf("can not open the file\n");
		return 0xC3;
        }
        fclose(fp);
	switch(reqptr[0])
        {
                case 0x00:
                        if(node_num == 0)
                        {
                                fp = fopen(NODE0HW1PWM,"w");
                                if(fp != NULL)
                                {
					buff1=reqptr[1];
					sprintf(buff,"%d",buff1);
                                        value = strtol(buff,NULL,10);
					fprintf(fp,"%d",value);
                                }
                                else
                                {
                                        printf("can not open the file\n");
					return 0xC3;
                                }
                                fclose(fp);
                        }
                        if(node_num == 1)
                        {
                                fp = fopen(NODE1HW1PWM,"w");
                                if(fp != NULL)
				{
					buff1=reqptr[1];
                                        sprintf(buff,"%d",buff1);
                                        value = strtol(buff,NULL,10);
                                        fprintf(fp,"%d",value);
                                }
                                else
                                {
                                        printf("can not open the file\n");
					return 0xC3;
                                }
                                fclose(fp);
                        }
                        break;
		case 0x02:
                        if(node_num == 0)
                        {
                                fp = fopen(NODE0HW2PWM,"w");
                                if(fp != NULL)
                                {
					buff1=reqptr[1];
                                        sprintf(buff,"%d",buff1);
                                        value = strtol(buff,NULL,10);
                                        fprintf(fp,"%d",value);
                                }
                                else
                                {
                                        printf("can not open the file\n");
					return 0xC3;
                                }
                                fclose(fp);
                        }
                        if(node_num == 1)
                        {
                                fp = fopen(NODE1HW2PWM,"w");
                                if(fp != NULL)
                                {
					buff1=reqptr[1];
                                        sprintf(buff,"%d",buff1);
                                        value = strtol(buff,NULL,10);
                                        fprintf(fp,"%d",value);
                                }
                                else
                                {
                                        printf("can not open the file\n");
					return 0xC3;
                                }
                                fclose(fp);
                        }
                        break;
                default:
                        return IPMI_CC_PARM_OUT_OF_RANGE;
        }
	*data_len = 0;
	return ipmi_rc;
}

ipmi_ret_t ipmi_arm_oem_get_fan_pwm(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
        FILE *fp;
        uint8_t *reqptr = (uint8_t *) request;
        ipmi_ret_t ipmi_rc = IPMI_CC_OK;
        char buff[5];
	int node_num = 0;
        char res[4];
        if(*data_len != 1)
        {
                return IPMI_CC_REQ_DATA_LEN_INVALID;
        }
	fp = fopen(GPIOG1FIlE, "r");
	if(fp != NULL)
	{
		fscanf(fp, "%s", buff);
                node_num=strtol(buff,NULL,10);
	}
	else
	{
		printf("can not open the file\n");
		return 0xC3;
	}
	fclose(fp);
	switch(reqptr[0])
	{
		case 0x00:
			if(node_num == 0)
			{
				fp = fopen(NODE0HW1PWM,"r");
				if(fp != NULL)
				{
					fscanf(fp, "%s", buff);
					res[0]=strtol(buff,NULL,10);
				}
				else
				{
					printf("can not open the file\n");
					return 0xC3;
				}
				fclose(fp);
			}
			if(node_num == 1)
			{
				fp = fopen(NODE1HW1PWM,"r");
                                if(fp != NULL)
                                {
                                        fscanf(fp, "%s", buff);
                                        res[0]=strtol(buff,NULL,10);
                                }
                                else
                                {
                                        printf("can not open the file\n");
					return 0xC3;
                                }
				fclose(fp);
			}
			break;
		case 0x02:
			if(node_num == 0)
                        {
                                fp = fopen(NODE0HW2PWM,"r");
                                if(fp != NULL)
                                {
                                        fscanf(fp, "%s", buff);
                                        res[0]=strtol(buff,NULL,10);
                                }
                                else
                                {
                                        printf("can not open the file\n");
					return 0xC3;
                                }
                                fclose(fp);
                        }
                        if(node_num == 1)
                        {
                                fp = fopen(NODE1HW2PWM,"r");
                                if(fp != NULL)
                                {
                                        fscanf(fp, "%s", buff);
                                        res[0]=strtol(buff,NULL,10);
                                }
                                else
                                {
                                        printf("can not open the file\n");
					return 0xC3;
				}
				fclose(fp);
			}
			break;
                default:
                        return IPMI_CC_PARM_OUT_OF_RANGE;
        }

	memcpy(response, res, *data_len);
        return ipmi_rc;
}

void register_netfn_none()
{
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n", NETFUN_NONE, IPMI_CMD_GET_PCIE_SLOT_STATUS);
    ipmi_register_callback(NETFUN_NONE, IPMI_CMD_GET_PCIE_SLOT_STATUS, NULL, ipmi_arm_oem_get_pcie_slot_status,
                           SYSTEM_INTERFACE);
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n", NETFUN_NONE, IPMI_CMD_GET_BMC_VENDOR);
    ipmi_register_callback(NETFUN_NONE, IPMI_CMD_GET_BMC_VENDOR, NULL, ipmi_arm_oem_get_bmc_vendor,
                           SYSTEM_INTERFACE);
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n", NETFUN_NONE, IPMI_CMD_GET_FAN_PWM);
    ipmi_register_callback(NETFUN_NONE, IPMI_CMD_GET_FAN_PWM, NULL, ipmi_arm_oem_get_fan_pwm,
                           SYSTEM_INTERFACE);
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n", NETFUN_NONE, IPMI_CMD_SET_FAN_SPEED);
    ipmi_register_callback(NETFUN_NONE, IPMI_CMD_SET_FAN_SPEED, NULL, ipmi_arm_oem_set_fan_speed,
                           SYSTEM_INTERFACE);
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n", NETFUN_NONE, IPMI_CMD_GET_NODE_ID_DETECTION);
    ipmi_register_callback(NETFUN_NONE, IPMI_CMD_GET_NODE_ID_DETECTION, NULL, ipmi_arm_oem_get_node_id_detection,
                           SYSTEM_INTERFACE);
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n", NETFUN_NONE, IPMI_CMD_GET_BROAD_ID_DETECTION);
    ipmi_register_callback(NETFUN_NONE, IPMI_CMD_GET_BROAD_ID_DETECTION, NULL, ipmi_arm_oem_get_broad_id_detection,
                           SYSTEM_INTERFACE);
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n", NETFUN_NONE, IPMI_CMD_SEND_SOC_MAC);
    ipmi_register_callback(NETFUN_NONE, IPMI_CMD_SEND_SOC_MAC,  NULL, ipmi_arm_oem_send_soc_mac,
                           SYSTEM_INTERFACE);
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n", NETFUN_NONE, IPMI_CMD_SEND_PLATFORM_MAC);
    ipmi_register_callback(NETFUN_NONE, IPMI_CMD_SEND_PLATFORM_MAC,  NULL, ipmi_arm_oem_send_platform_mac,
                           SYSTEM_INTERFACE);
}

void register_netfn_qdt_oem()
{
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n", NETFUN_QDT_OEM, IPMI_CMD_SET_BOOT_MODE);
    ipmi_register_callback(NETFUN_QDT_OEM, IPMI_CMD_SET_BOOT_MODE, NULL, ipmi_qdt_oem_set_boot_mode,
                           SYSTEM_INTERFACE);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n", NETFUN_QDT_OEM, IPMI_CMD_GET_BOOT_MODE);
    ipmi_register_callback(NETFUN_QDT_OEM, IPMI_CMD_GET_BOOT_MODE, NULL, ipmi_qdt_oem_get_boot_mode,
                           SYSTEM_INTERFACE);
}
