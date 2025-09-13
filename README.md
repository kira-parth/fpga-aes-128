# AES-128 Hardware Accelerator on Zynq FPGA

This project implements an **AES-128 encryption/decryption accelerator** using **Vitis HLS** and integrates it into a **Zynq SoC design** (tested on PYNQ-Z2).  
It offloads the computationally expensive AES algorithm into FPGA fabric while communicating with the ARM processing system via **AXI DMA**.

---

##  Features
- AES-128 encryption and decryption (ECB mode).
- High-Level Synthesis (C/C++) design for portability.
- AXI4-Stream and AXI4-Lite interfaces for easy integration.
- Works with AXI DMA for high-speed data transfer.
- Integrated into Zynq Processing System (PS + PL).



---

## 🖼 Block Design
<img width="1551" height="732" alt="Screenshot 2025-09-14 010544" src="https://github.com/user-attachments/assets/1844961e-040d-4706-b93f-e9fb44a9c438" />


---

## 🔋 Power Report
<img width="1486" height="878" alt="Screenshot 2025-09-14 010621" src="https://github.com/user-attachments/assets/3fef738c-7047-4d65-a5ee-a7c585a9e0ee" />



## 🛠️ How to Build & Run
### Prerequisites
- Xilinx Vivado 2020.2+
- Vitis HLS
- PYNQ-Z2 (or any Zynq-7000 board)

### Steps
1. Open `src/` in **Vitis HLS**, run C-simulation & synthesis.
2. Export RTL, then import into Vivado IP Integrator.
3. Recreate the block design (see `design_bd.png`).
4. Connect AXI DMA between PS and AES IP.
5. Generate Bitstream, export XSA, and build with Vitis.
6. Test on hardware using bare-metal C program / PYNQ Python.

---

##  License
MIT License

[Untitled.ipynb](https://github.com/user-attachments/files/22314707/Untitled.ipynb)
