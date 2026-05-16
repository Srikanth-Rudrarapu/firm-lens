class STM32Extractor:
    """
    Lightweight metadata extractor for STM32 firmware images.

    This extractor does NOT parse the actual flash contents.
    It simply returns static metadata commonly associated with STM32 MCUs:

      • Flash size (example: 1MB)
      • Vector table base address (0x08000000 for most STM32 parts)

    Deep analysis is handled by analyzers, not this extractor.
    """

    def extract(self, firmware_path: str):
        return {
            "chip": "STM32",
            "flash_size": "1MB",
            "vector_table": "0x08000000",
        }
