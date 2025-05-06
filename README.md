# rclone_mysql
Package mysql provides secure MySQL backup functionality with AES-256 encryption, ZIP compression, and cloud storage integration using Rclone.

/*
Package mysql provides secure MySQL backup functionality with AES-256 encryption,
ZIP compression, and cloud storage integration using Rclone.

Features:
- Configuration file encryption/decryption
- Database connection validation
- mysqldump with progress tracking
- Optional ZIP compression
- Cloud upload via Rclone
- INI-style configuration management

config.txt sample
[db_development]
server=156.107.98.9
port=3306
db=u2233041_scademo
user=u2233041_dev
pass=lad34@c3BayfT

[db_production]
server=156.107.98.9
port=3306
db=u8632635_sg
user=u8632635_dev
pass=ldad34@c3BayfT

[remote_pcloudtest]
type=pcloud
hostname=api.pcloud.com
token={"access_token":"OanIZDnONS8yy6opk","token_type":"bearer","expiry":"0001-01-01T00:00:00Z"}

[general]
rclone_path=/home/sov/rclone/rclone

==================================================

To compile:
go build -tags=crypt -o rclone

Criptografar arquivo de configuração:
./rclone mysql --crip config.txt

Backup básico:
./rclone mysql --database db_production

Backup com compactação ZIP:
./rclone mysql --database db_development --zip

Backup completo (compactação + upload):
./rclone mysql -d db_production -z -r pcloudtest:/folder

