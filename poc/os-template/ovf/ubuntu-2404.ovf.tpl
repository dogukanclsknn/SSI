<?xml version="1.0" encoding="UTF-8"?>
<!-- SSI OS template PoC: OVF 1.0 descriptor filled in by host/export.sh (@...@ placeholders). -->
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1" xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1" xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData" xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData" xmlns:vmw="http://www.vmware.com/schema/ovf" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <References>
    <File ovf:id="file1" ovf:href="@VMDK_FILE@" ovf:size="@VMDK_SIZE@"/>
  </References>
  <DiskSection>
    <Info>Virtual disks</Info>
    <Disk ovf:diskId="vmdisk1" ovf:fileRef="file1" ovf:capacity="@CAPACITY_BYTES@" ovf:capacityAllocationUnits="byte" ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"/>
  </DiskSection>
  <NetworkSection>
    <Info>Logical networks</Info>
    <Network ovf:name="VM Network">
      <Description>The network the VM connects to; chosen at import time.</Description>
    </Network>
  </NetworkSection>
  <VirtualSystem ovf:id="@NAME@">
    <Info>SSI OS template @NAME@ @VERSION@</Info>
    <Name>@NAME@-@VERSION@</Name>
    <AnnotationSection>
      <Info>Template provenance</Info>
      <Annotation>SSI OS template @NAME@ @VERSION@ (build @BUILD_ID@). Verify SHA256SUMS and the cosign signature before import.</Annotation>
    </AnnotationSection>
    <OperatingSystemSection ovf:id="94" vmw:osType="ubuntu64Guest">
      <Info>Guest operating system</Info>
      <Description>Ubuntu Linux (64-bit)</Description>
    </OperatingSystemSection>
    <!-- First-boot settings asked at import (vCenter "Customize template"); cloud-init's OVF
         datasource reads them through VMware Tools (open-vm-tools is in the template). -->
    <ProductSection ovf:required="false">
      <Info>First-boot settings (cloud-init)</Info>
      <Product>SSI OS template @NAME@</Product>
      <Version>@VERSION@</Version>
      <Property ovf:key="instance-id" ovf:type="string" ovf:userConfigurable="true" ovf:value="@NAME@">
        <Label>Instance ID</Label>
        <Description>Unique ID for this VM; change it to make cloud-init run again.</Description>
      </Property>
      <Property ovf:key="hostname" ovf:type="string" ovf:userConfigurable="true" ovf:value="">
        <Label>Hostname</Label>
        <Description>Host name of the new VM.</Description>
      </Property>
      <Property ovf:key="public-keys" ovf:type="string" ovf:userConfigurable="true" ovf:value="">
        <Label>SSH public key</Label>
        <Description>Added to the default user (ubuntu). The template holds no password or key of its own.</Description>
      </Property>
      <Property ovf:key="user-data" ovf:type="string" ovf:userConfigurable="true" ovf:value="">
        <Label>cloud-init user data (base64)</Label>
        <Description>Optional cloud-config, base64 encoded.</Description>
      </Property>
    </ProductSection>
    <VirtualHardwareSection ovf:transport="com.vmware.guestInfo">
      <Info>Virtual hardware requirements</Info>
      <System>
        <vssd:ElementName>Virtual Hardware Family</vssd:ElementName>
        <vssd:InstanceID>0</vssd:InstanceID>
        <vssd:VirtualSystemIdentifier>@NAME@-@VERSION@</vssd:VirtualSystemIdentifier>
        <vssd:VirtualSystemType>vmx-15</vssd:VirtualSystemType>
      </System>
      <Item>
        <rasd:AllocationUnits>hertz * 10^6</rasd:AllocationUnits>
        <rasd:Description>Number of virtual CPUs</rasd:Description>
        <rasd:ElementName>@CPUS@ virtual CPU(s)</rasd:ElementName>
        <rasd:InstanceID>1</rasd:InstanceID>
        <rasd:ResourceType>3</rasd:ResourceType>
        <rasd:VirtualQuantity>@CPUS@</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits>
        <rasd:Description>Memory size</rasd:Description>
        <rasd:ElementName>@MEMORY_MB@ MB of memory</rasd:ElementName>
        <rasd:InstanceID>2</rasd:InstanceID>
        <rasd:ResourceType>4</rasd:ResourceType>
        <rasd:VirtualQuantity>@MEMORY_MB@</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:Address>0</rasd:Address>
        <rasd:Description>SCSI Controller</rasd:Description>
        <rasd:ElementName>SCSI Controller 0</rasd:ElementName>
        <rasd:InstanceID>3</rasd:InstanceID>
        <rasd:ResourceSubType>lsilogic</rasd:ResourceSubType>
        <rasd:ResourceType>6</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:AddressOnParent>0</rasd:AddressOnParent>
        <rasd:ElementName>Hard Disk 1</rasd:ElementName>
        <rasd:HostResource>ovf:/disk/vmdisk1</rasd:HostResource>
        <rasd:InstanceID>4</rasd:InstanceID>
        <rasd:Parent>3</rasd:Parent>
        <rasd:ResourceType>17</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:AddressOnParent>7</rasd:AddressOnParent>
        <rasd:AutomaticAllocation>true</rasd:AutomaticAllocation>
        <rasd:Connection>VM Network</rasd:Connection>
        <rasd:Description>VmxNet3 ethernet adapter on "VM Network"</rasd:Description>
        <rasd:ElementName>Network adapter 1</rasd:ElementName>
        <rasd:InstanceID>5</rasd:InstanceID>
        <rasd:ResourceSubType>VmxNet3</rasd:ResourceSubType>
        <rasd:ResourceType>10</rasd:ResourceType>
      </Item>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>
