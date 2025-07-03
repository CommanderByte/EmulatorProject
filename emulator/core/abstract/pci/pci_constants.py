# Standard PCI Configuration Space Offsets
PCI_VENDOR_ID      = 0x00
PCI_DEVICE_ID      = 0x02
PCI_COMMAND        = 0x04
PCI_STATUS         = 0x06
PCI_REVISION_ID    = 0x08
PCI_PROG_IF        = 0x09
PCI_SUBCLASS       = 0x0A
PCI_CLASS_CODE     = 0x0B
PCI_CACHE_LINE_SIZE= 0x0C
PCI_LATENCY_TIMER  = 0x0D
PCI_HEADER_TYPE    = 0x0E
PCI_BIST           = 0x0F

PCI_BAR0           = 0x10  # 6 x 4-byte BARs for Type 0 headers
PCI_BAR_COUNT      = 6

PCI_CAPABILITY_POINTER = 0x34
PCI_INTERRUPT_LINE     = 0x3C
PCI_INTERRUPT_PIN      = 0x3D

# PCI Command Register Flags
PCI_COMMAND_IO         = 0x1
PCI_COMMAND_MEMORY     = 0x2
PCI_COMMAND_BUS_MASTER = 0x4

# PCI Header Types
PCI_HEADER_TYPE_NORMAL = 0x00
PCI_HEADER_TYPE_BRIDGE = 0x01
PCI_HEADER_TYPE_CARDBUS= 0x02

# Capability IDs (used in PCI capabilities list)
PCI_CAP_ID_PM      = 0x01  # Power Management
PCI_CAP_ID_AGP     = 0x02
PCI_CAP_ID_VPD     = 0x03
PCI_CAP_ID_SLOTID  = 0x04
PCI_CAP_ID_MSI     = 0x05  # Message Signaled Interrupts
PCI_CAP_ID_HOTPLUG = 0x06
PCI_CAP_ID_PCIX    = 0x07
PCI_CAP_ID_HT      = 0x08  # HyperTransport
PCI_CAP_ID_VNDR    = 0x09  # Vendor-Specific
PCI_CAP_ID_DEBUG   = 0x0A
PCI_CAP_ID_CPCI_HS = 0x0B
PCI_CAP_ID_PCIX2   = 0x0C
PCI_CAP_ID_AF      = 0x0D  # Advanced Features


# CF8/0xCF8: CONFIG_ADDRESS (write)
# CFC/0xCFC: CONFIG_DATA (read/write)
PCI_CONFIG_ADDRESS_PORT = 0xCF8
PCI_CONFIG_DATA_PORT    = 0xCFC