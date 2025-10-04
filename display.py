import os

class DisplayBase:
    def clear(self): pass
    def text(self, s, x, y): pass
    def button(self, label, pos): pass
    def show_qr(self, qr, label=""): pass

class VirtualDisplay(DisplayBase):
    def clear(self): print("\n" * 3)
    def text(self, s, x=0, y=0): print(s)
    def button(self, label, pos): print(f"[{pos}] {label}")
    def show_qr(self, qr, label=""): print(f"[QR {label}]\n{qr.terminal()}\n")

# Add the real ST7789 implementation here
# e.g. using the luma.lcd library or the official waveshare_st7789 driver
def get_display(driver="virtual"):
    if driver.lower().startswith("st"):
        # TODO: implement waveshare ST7789 driver
        raise NotImplementedError("ST7789 driver to be added")
    return VirtualDisplay()
