#include <stdint.h>
#include <host-ipmid/ipmid-api.h>

enum ipmi_net_fns_oem
{
    NETFUN_QDT_OEM = 0x2E,
};

enum ipmi_net_fns_oem_cmds
{
    IPMI_CMD_SET_BOOT_MODE = 0xC2,
    IPMI_CMD_GET_BOOT_MODE = 0xC3,
};

enum ipmi_netfn_none_cmds
{
    IPMI_CMD_GET_PCIE_SLOT_STATUS = 0x13,
    IPMI_CMD_GET_BMC_VENDOR = 0x14,
    IPMI_CMD_GET_FAN_PWM = 0x20,
    IPMI_CMD_SET_FAN_SPEED = 0x21,
    IPMI_CMD_GET_NODE_ID_DETECTION = 0x24,
    IPMI_CMD_GET_BROAD_ID_DETECTION = 0x25,
    IPMI_CMD_SEND_SOC_MAC = 0x29,
    IPMI_CMD_SEND_PLATFORM_MAC = 0x2A,
};

ipmi_ret_t ipmi_arm_oem_get_pcie_slot_status(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context);

ipmi_ret_t ipmi_arm_oem_get_bmc_vendor(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context);

ipmi_ret_t ipmi_arm_oem_get_node_id_detection(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context);

ipmi_ret_t ipmi_arm_oem_get_broad_id_detection(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context);

ipmi_ret_t ipmi_arm_oem_send_soc_mac(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context);

ipmi_ret_t ipmi_arm_oem_send_platform_mac(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context);

ipmi_ret_t ipmi_qdt_oem_set_boot_mode(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context);

ipmi_ret_t ipmi_qdt_oem_get_boot_mode(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context);
