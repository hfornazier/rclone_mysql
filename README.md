📦 rclone mysql — Secure and Free MySQL Backup
Plugin for rclone that performs MySQL database backups with:
•	🔐 System-bound encryption
•	📦 ZIP compression
•	☁️ Upload to any storage supported by rclone (Drive, PCloud, S3, etc.)
•	💡 Open source with environment-based security
•	📅 Easy integration with cron (Linux) or Task Scheduler (Windows)
🔒 Security: How it works The configuration file (rclone-config.enc) is encrypted with a key derived from the system environment (OS, hostname, user, and path).
•	✅ This ensures:
o	It can only be used on the same computer where it was generated.
o	Even with access to the code, the secret resides in the environment — not in the logic.
o	This technique is known as environmental binding, used in highly secure software.
⚙️ Compilation
go build -tags=crypt -o rclone
The output will be the rclone binary with the integrated plugin.
🧾 Initial Configuration Create a config.txt file with the data:

[db_development]
server = 192.155.1.13
port = 3306
db = u2233041_base1
user = u2233041_adm
pass = lad3455@c3BayfT

[db_production]
server = 154.107.67.5
port = 3306
db = u863235_sg
user = u863235_adm
pass = lda455@c3BayfT

[remote_pcloudtest]
type = pcloud
hostname = api.pcloud.com
token = {"access_token": "OanIZopk", "token_type": "bearer", "expiry": "0001-01-01T00:00:00Z"}

[remote_onedrivetest]
type = drive
scope = drive
token = {"access_token": "ya29...", "expiry": "2020-01-11T10:20:10.2771957-03:00"}

[general]
rclone_path = /home/humberto/backup-mysql
mysqldump_path = /usr/bin/mysqldump

[email]
smtp_server = smtp.seuprovedor.com
smtp_port = 587
smtp_user = backup@seudominio.com
smtp_pass = senhasupersecreta
from = backup@seudominio.com
to = admin@gmail.com,suporte@seudominio.com
use_tls = true

🔐 Encrypt the Configuration
./rclone mysql --crip config.txt
After encrypting, remove the config.txt. Generated file: rclone-config.enc

🚀 Usage Examples

# Local backup (no upload)
./rclone mysql --database db_development

# Backup + ZIP
./rclone mysql --database db_development --zip

# Backup + ZIP + Upload
./rclone mysql --database db_development --zip --remote pcloudtest:/backups/mysql

# Shortcuts
./rclone mysql -d db_production -z -r pcloudtest:/prod

📧 Email Notifications After Backup You can now be automatically notified by email after the backup.

🔧 Parameters
•	--emailsucess → sends email only in case of success.
•	--emailerr → sends email only if there is an error. Both can be used together.
•	
🛠️ [email] Section Configuration (before encryption)
[email]
smtp_server = smtp.seudominio.com
smtp_port = 465
smtp_user = user
smtp_pass = password
from = notification@yourdomain.com
to = destination@example.com,support@example.com

The connection mode is automatically defined:
•	Ports 465 → SMTPS
•	Ports 587 → STARTTLS
📎 Command Example with Notification
./rclone mysql -d db_production -z -r pcloudtest:/backup --emailsucess --emailerr
📌 Logs are generated in case of sending errors (authentication, invalid recipient, etc.).



📅 Automation with Cron (Linux)
# Daily backup at 2am
0 2 * * * /home/user/rclone mysql -d db_production -z -r pcloudtest:/backups

# With full path
0 2 * * * /home/user/rclone/rclone mysql -d db_development -z -r drive:/mysql-backups

📁 Generated Files Structure
bbksql/
├── db_development_20250405_103022.sql    # (without -z)
└── db_development_20250405_103022.zip    # (with -z)
⚠️ Limitations
•	The rclone-config.enc file only works on the computer where it was generated.
•	The system requires mysqldump installed (on Windows it must be in the same folder as rclone).
•	
🔍 Check Plugin Version
./rclone mysql –mysqlversion
📤 Output: MySQL Backup Plugin v1.0.0

🎁 Bonus: Free Linux VM (Forever!) on Oracle Cloud Run backups 24/7 on a free VM:
•	💻 1 OCPU and 1 GB RAM (Ampere A1)
•	💾 20 GB storage
•	🌐 Fixed IP
•	🆓 100% free — no expiration!
💡 How to set up:
1.	Access: [Oracle Cloud Free Tier](https://www.oracle.com/cloud/free/)
2.	Create an account (card required, but no charges)
3.	Create a VM.Standard.A1.Flex (1 OCPU, 1 GB RAM)
4.	Use Ubuntu 22.04 or 24.04
5.	Install rclone + MySQL client
📜 License MIT — Free to use, modify, and distribute.
Made with ❤️ for those who love automation, security, and clean code.

