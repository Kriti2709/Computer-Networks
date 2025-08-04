🔥 Firewall Simulation GUI – Python Project
This project is a **Graphical User Interface (GUI) based Firewall Simulator** built using Python and `Tkinter`. It allows users to define and manage firewall rules, simulate network packets, and monitor their status (allowed or blocked) in real-time.
🛠 Features
* Add or remove firewall rules based on:
  * Source IP
  * Destination IP
  * Protocol (TCP/UDP/ICMP)
  * Port number
  * Action (ALLOW or BLOCK)
* Real-time log of simulated packets.
* Random packet generation.
* Default behavior: BLOCK unknown traffic for better security.
* Intuitive and easy-to-use GUI using Tkinter.

📦 Technologies Used
Python 3
Tkinter** – for GUI
`re`, `random`, `threading`, `time`, `collections` – for backend logic and performance

🚀 How to Run
1. Make sure you have Python installed (3.x version).
2. Run the script:
   ```bash
   python "Computer Networks.py"
   ```
3. The GUI will open:
   * Add rules using the form
   * Generate packets to test rule matching
   * View logs in the bottom section

📸 Screenshots (Optional)
<img width="898" height="797" alt="image" src="https://github.com/user-attachments/assets/a15b6e58-54ac-488c-90cb-ea2d7dbc0df6" />
<img width="1079" height="789" alt="image" src="https://github.com/user-attachments/assets/98a3a4cd-c99a-40d6-b336-af85472f67e8" />

📚 Learning Goals
This project helps you understand:
* How firewall rules work conceptually
* Basic packet structure and network protocols
* GUI development using Tkinter
* Real-time logging and multithreading

🤝 Contributing
Contributions are welcome! Feel free to fork the repo and submit a pull request.

📄 License
This project is for educational use. You may adapt or reuse with proper credit.
