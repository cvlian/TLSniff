/* layer-vlan.h
 *
 * routines for the VLAN 802.1Q ethernet packet parsing
 *  
 * TLSniff - a fast and simple tool to analyze SSL/TLS records 
 */

#ifndef PUMP_LAYER_VLAN
#define PUMP_LAYER_VLAN

#include "layer.h"

#pragma pack(push, 1)
    struct vlan_header {
        uint16_t vlan;
        /** Ethernet type for next layer */
        uint16_t etherType;
    };
#pragma pack(pop)

#pragma pack(push, 1)
    struct vxlan_header
    {
        #if(BYTE_ORDER == LITTLE_ENDIAN)
            /** Reserved bits */
            uint16_t reserved6_8:3;
            /** VNI present flag */
            uint16_t vniPresentFlag:1;
            /** Reserved bits */
            uint16_t reserved2_4:3;
            /** GBP flag */
            uint16_t gbpFlag:1;
            /** Reserved bits */
            uint16_t reserved14_16:3;
            /** Policy applied flag */
            uint16_t policyAppliedFlag:1;
            /** Reserved bits */
            uint16_t reserved11_12:2;
            /** Don't learn flag */
            uint16_t dontLearnFlag:1;
            /** Reserved bits */
            uint16_t reserved9:1;
        #else
            /** Reserved bits */
            uint16_t reserved9:1;
            /** Don't learn flag */
            uint16_t dontLearnFlag:1;
            /** Reserved bits */
            uint16_t reserved11_12:2;
            /** Policy applied flag */
            uint16_t policyAppliedFlag:1;
            /** Reserved bits */
            uint16_t reserved14_16:3;
            /** GBP flag */
            uint16_t gbpFlag:1;
            /** Reserved bits */
            uint16_t reserved2_4:3;
            /** VNI present flag */
            uint16_t vniPresentFlag:1;
            /** Reserved bits */
            uint16_t reserved6_8:3;
        #endif

        /** Group Policy ID */
        uint16_t groupPolicyID;
        /** VXLAN Network ID (VNI) */
        uint32_t vni:24;
        /** Reserved bits */
        uint32_t pad:8;
    };
#pragma pack(pop)

namespace pump
{

    class VlanLayer : public Layer
    {

        public:

            VlanLayer(uint8_t* data, size_t dataLen, Layer* prevLayer) : Layer(data, dataLen, prevLayer) { l_Protocol = PROTO_VLAN; }

            ~VlanLayer() {}

            void parseNextLayer();

            uint8_t getOsiModelLayer() const { return OSI_DataLinkLayer; }

            vlan_header* getVlanHeader() const { return (vlan_header*)l_Data; }

            size_t getHeaderLen() const { return sizeof(vlan_header); }

    };

    class VxlanLayer : public Layer
    {
        
        public:

            VxlanLayer(uint8_t* data, size_t dataLen, Layer* prevLayer) : Layer(data, dataLen, prevLayer) { l_Protocol = PROTO_VXLAN; }

            ~VxlanLayer() {}

            void parseNextLayer();

            uint8_t getOsiModelLayer() const { return OSI_DataLinkLayer; }

            size_t getHeaderLen() const { return sizeof(vxlan_header); }

            static bool isVxlanPort(uint16_t port) { return port == 4789; }

    };
}

#endif