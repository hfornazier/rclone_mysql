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

*/

package mysql

import (
    "archive/zip"
    "bufio"
    "context"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "database/sql"
    "fmt"
    "io"
    "io/ioutil"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "time"

    "github.com/rclone/rclone/cmd"
    "github.com/rclone/rclone/fs/config/flags"
    "github.com/spf13/cobra"
    "github.com/dustin/go-humanize"
    _ "github.com/go-sql-driver/mysql"    
)

const fixedKey = "7f8g3h4j9k0l1m2n5o6p7q8r9s0tuvwx" // Chave AES-256 de 32 caracteres

var (
    criptFlag    bool
    databaseFlag string
    zipFlag      bool
    remoteFlag   string
    startTime    time.Time
)

func init() {
    cmd.Root.AddCommand(commandDefinition)
    cmdFlags := commandDefinition.Flags()
    
    flags.BoolVarP(cmdFlags, &criptFlag, "crip", "", false, "Criptografar arquivo de configuração", "")
    flags.StringVarP(cmdFlags, &databaseFlag, "database", "d", "", "Seção do banco de dados", "")
    flags.BoolVarP(cmdFlags, &zipFlag, "zip", "z", false, "Compactar backup em ZIP", "")
    flags.StringVarP(cmdFlags, &remoteFlag, "remote", "r", "", "Destino remoto (ex: 'meu_remote:backups')", "")
}

var commandDefinition = &cobra.Command{
    Use:   "mysql",
    Short: "Backup MySQL com criptografia e upload para nuvem",
    Run: func(command *cobra.Command, args []string) {
        if criptFlag {
            handleEncryption(args)
            return
        }
        handleBackup()
    },
}

// Função principal de criptografia
func handleEncryption(args []string) {
    if len(args) == 0 {
        fmt.Println("Erro: Informe o arquivo de configuração")
        fmt.Println("Exemplo: ./rclone mysql --crip config.txt")
        return
    }
    
    if err := encryptFile(args[0], "rclone.my"); err != nil {
        fmt.Printf("Erro na criptografia: %v\n", err)
    } else {
        fmt.Println("Configuração criptografada salva em: rclone.my")
    }
}

// Função principal de backup
func handleBackup() {
    if databaseFlag == "" {
        fmt.Println("Erro: Especifique a seção do banco com --database")
        return
    }

    content, err := decryptFile("rclone.my")
    if err != nil {
        fmt.Printf("Erro na descriptografia: %v\n", err)
        return
    }

    databases, remotes, err := parseSections(content)
    if err != nil {
        fmt.Printf("Erro lendo configuração: %v\n", err)
        return
    }

    credentials, ok := databases[databaseFlag]
    if !ok {
        fmt.Printf("Seção '%s' não encontrada\n", databaseFlag)
        return
    }

    if err := validateCredentials(credentials); err != nil {
        fmt.Println(err)
        return
    }

    if err := executeBackup(credentials, remotes); err != nil {
        fmt.Printf("Erro no backup: %v\n", err)
    }
}

// Processa as seções do arquivo de configuração
func parseSections(content string) (map[string]map[string]string, map[string]map[string]string, error) {
    databases := make(map[string]map[string]string)
    remotes := make(map[string]map[string]string)
    var currentSection string

    scanner := bufio.NewScanner(strings.NewReader(content))
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }

        if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
            currentSection = strings.Trim(line, "[]")
            if strings.HasPrefix(currentSection, "remote_") {
                remotes[currentSection] = make(map[string]string)
            } else {
                databases[currentSection] = make(map[string]string)
            }
            continue
        }

        if currentSection != "" {
            parts := strings.SplitN(line, "=", 2)
            if len(parts) == 2 {
                key := strings.TrimSpace(parts[0])
                value := strings.TrimSpace(parts[1])
                
                if strings.HasPrefix(currentSection, "remote_") {
                    remotes[currentSection][key] = value
                } else {
                    databases[currentSection][key] = value
                }
            }
        }
    }
    return databases, remotes, scanner.Err()
}

// Criptografa o arquivo de configuração
func encryptFile(inputFile, outputFile string) error {
    data, err := ioutil.ReadFile(inputFile)
    if err != nil {
        return fmt.Errorf("erro lendo arquivo: %v", err)
    }

    block, err := aes.NewCipher([]byte(fixedKey))
    if err != nil {
        return err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err = rand.Read(nonce); err != nil {
        return err
    }

    ciphertext := gcm.Seal(nonce, nonce, data, nil)
    return ioutil.WriteFile(outputFile, ciphertext, 0644)
}

// Descriptografa o arquivo de configuração
func decryptFile(fileName string) (string, error) {
    data, err := ioutil.ReadFile(fileName)
    if err != nil {
        return "", fmt.Errorf("erro lendo arquivo: %v", err)
    }

    block, err := aes.NewCipher([]byte(fixedKey))
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonceSize := gcm.NonceSize()
    if len(data) < nonceSize {
        return "", fmt.Errorf("arquivo criptografado inválido")
    }

    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    return string(plaintext), err
}

// Valida as credenciais do banco de dados
func validateCredentials(credentials map[string]string) error {
    required := []string{"server", "port", "db", "user", "pass"}
    for _, field := range required {
        if credentials[field] == "" {
            return fmt.Errorf("campo obrigatório faltando: '%s'", field)
        }
    }
    return nil
}

// Executa o processo completo de backup
func executeBackup(credentials map[string]string, remotes map[string]map[string]string) error {
    startTime = time.Now() // Inicialize aqui
    
    db, err := connectToMySQL(credentials)
    if err != nil {
        return err
    }
    defer db.Close()
    
    backupFile, err := createBackupFile(credentials)
    if err != nil {
        return err
    }

    // Mostrar estatísticas após o backup
    fileInfo, _ := os.Stat(backupFile)
    fmt.Printf("\n✓ Backup SQL concluído:\n- Tamanho: %s\n- Duração: %v\n",
        humanize.Bytes(uint64(fileInfo.Size())),
        time.Since(startTime).Round(time.Second),
    )    

    if zipFlag {
        if zippedFile, err := compressBackup(backupFile); err == nil {
            backupFile = zippedFile
        } else {
            return err
        }
    }

    if shouldUpload(credentials) {
        if err := uploadBackup(backupFile, remotes); err != nil {
            return err
        }
    }

    fmt.Printf("\n✓ Backup concluído: %s\n", backupFile)
    return nil
}

// Conecta ao banco de dados MySQL
func connectToMySQL(credentials map[string]string) (*sql.DB, error) {
    dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s",
        credentials["user"],
        credentials["pass"],
        credentials["server"],
        credentials["port"],
        credentials["db"],
    )

    db, err := sql.Open("mysql", dsn)
    if err != nil {
        return nil, fmt.Errorf("erro conectando ao MySQL: %v", err)
    }

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    if err := db.PingContext(ctx); err != nil {
        return nil, fmt.Errorf("erro verificando conexão: %v", err)
    }
    return db, nil
}

// Cria o arquivo de backup SQL
func createBackupFile(credentials map[string]string) (string, error) {
    backupDir := "bbksql"
    if err := os.MkdirAll(backupDir, 0755); err != nil {
        return "", fmt.Errorf("erro criando diretório: %v", err)
    }

    timestamp := time.Now().Format("20060102_150405")
    fileName := filepath.Join(backupDir, fmt.Sprintf("%s_%s.sql", databaseFlag, timestamp))

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
    defer cancel()

    cmd := exec.CommandContext(ctx, "mysqldump",
        "-h", credentials["server"],
        "-P", credentials["port"],
        "-u", credentials["user"],
        fmt.Sprintf("-p%s", credentials["pass"]),
        "--ssl-mode=DISABLED",
        "--max-allowed-packet=512M",
        "--single-transaction",
        "--quick",
        "--verbose", // Mostra informações de progresso
        "--log-error=backup_errors.log",
        credentials["db"],
    )

    // Capturar saída de erro para mostrar progresso
    stderr, err := cmd.StderrPipe()
    if err != nil {
        return "", err
    }

    outFile, err := os.Create(fileName)
    if err != nil {
        return "", err
    }

    cmd.Stdout = outFile

    // Iniciar o comando
    if err := cmd.Start(); err != nil {
        return "", fmt.Errorf("erro iniciando mysqldump: %v", err)
    }

    // Mostrar animação de progresso
    done := make(chan bool)
    go func() {
        spinner := []string{"|", "/", "-", "\\"}
        i := 0
        for {
            select {
            case <-done:
                return
            default:
                fmt.Printf("\rExecutando mysqldump %s", spinner[i%4])
                time.Sleep(100 * time.Millisecond)
                i++
            }
        }
    }()

    // Ler saída de erro em tempo real
    scanner := bufio.NewScanner(stderr)
    go func() {
        for scanner.Scan() {
            fmt.Printf("\r\033[K%s\n", scanner.Text())
        }
    }()

    // Aguardar conclusão
    if err := cmd.Wait(); err != nil {
        done <- true
        return "", fmt.Errorf("erro no mysqldump: %v", err)
    }

    done <- true
    fmt.Printf("\r\033[KMysqldump concluído com sucesso!\n")

    // Mostrar estatísticas
    fileInfo, _ := os.Stat(fileName)
    fmt.Printf("\nTamanho do backup: %s\n", humanize.Bytes(uint64(fileInfo.Size())))
    fmt.Printf("Tempo total: %v\n\n", time.Since(startTime).Round(time.Second))

    return fileName, nil
}

// Compacta o backup para ZIP
func compressBackup(sqlFile string) (string, error) {
    zipFile := strings.TrimSuffix(sqlFile, ".sql") + ".zip"
    
    zipWriter, err := os.Create(zipFile)
    if err != nil {
        return "", err
    }
    defer zipWriter.Close()

    archive := zip.NewWriter(zipWriter)
    defer archive.Close()

    file, err := os.Open(sqlFile)
    if err != nil {
        return "", err
    }
    defer file.Close()

    info, err := file.Stat()
    if err != nil {
        return "", err
    }

    header, err := zip.FileInfoHeader(info)
    if err != nil {
        return "", err
    }

    header.Name = filepath.Base(sqlFile)
    header.Method = zip.Deflate

    writer, err := archive.CreateHeader(header)
    if err != nil {
        return "", err
    }

    if _, err = io.Copy(writer, file); err != nil {
        return "", err
    }

    os.Remove(sqlFile) // Remove arquivo SQL original
    return zipFile, nil
}

// Verifica se deve fazer upload
func shouldUpload(credentials map[string]string) bool {
    return remoteFlag != "" || credentials["remote"] != ""
}

// Faz upload para a nuvem
func uploadBackup(backupFile string, remotes map[string]map[string]string) error {
    remoteToUse := getRemoteTarget()
    if remoteToUse == "" {
        remoteToUse = getDefaultRemote(remotes)
    }

    if remoteToUse == "" {
        return fmt.Errorf("nenhum remote especificado")
    }

    remoteConfig, err := getRemoteConfig(remoteToUse, remotes)
    if err != nil {
        return err
    }

    rclonePath, err := findRclonePath(remotes)
    if err != nil {
        return err
    }

    return executeRcloneUpload(rclonePath, backupFile, remoteToUse, remoteConfig)
}

// Obtém o remote alvo
func getRemoteTarget() string {
    if remoteFlag != "" {
        return remoteFlag
    }
    return ""
}

// Obtém o remote padrão da configuração
func getDefaultRemote(remotes map[string]map[string]string) string {
    for name := range remotes {
        if strings.HasPrefix(name, "remote_") {
            return strings.TrimPrefix(name, "remote_") + ":"
        }
    }
    return ""
}

// Obtém a configuração do remote
func getRemoteConfig(remote string, remotes map[string]map[string]string) (map[string]string, error) {
    parts := strings.SplitN(remote, ":", 2)
    remoteName := "remote_" + parts[0]
    
    config, exists := remotes[remoteName]
    if !exists {
        available := make([]string, 0, len(remotes))
        for k := range remotes {
            available = append(available, strings.TrimPrefix(k, "remote_"))
        }
        return nil, fmt.Errorf("remote '%s' não encontrado. Disponíveis: %v", parts[0], available)
    }
    return config, nil
}

// Localiza o executável do RClone
func findRclonePath(remotes map[string]map[string]string) (string, error) {
    if path, ok := remotes["general"]["rclone_path"]; ok {
        if _, err := os.Stat(path); err == nil {
            return path, nil
        }
    }

    execDir, _ := os.Executable()
    execDir = filepath.Dir(execDir)

    locations := []string{
        filepath.Join(execDir, "rclone"),
        filepath.Join(execDir, "rclone.exe"),
        "/usr/bin/rclone",
        "/usr/local/bin/rclone",
        "C:\\Program Files\\rclone\\rclone.exe",
        "rclone",
    }

    for _, path := range locations {
        if _, err := os.Stat(path); err == nil {
            return path, nil
        }
    }

    return "", fmt.Errorf("rclone não encontrado. Verifique a instalação")
}

// Executa o comando RClone para upload
func executeRcloneUpload(rclonePath, backupFile, remoteDest string, config map[string]string) error {
    parts := strings.SplitN(remoteDest, ":", 2)
    remoteName := parts[0]
    
    tempConfig, err := createTempConfig(remoteName, config)
    if err != nil {
        return err
    }
    defer os.Remove(tempConfig)

    ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
    defer cancel()

    cmd := exec.CommandContext(ctx, rclonePath,
        "--config", tempConfig,
        "copy",
        backupFile,
        remoteDest,
        "--progress",
    )

    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr

    return cmd.Run()
}

// Cria configuração temporária para o RClone
func createTempConfig(remoteName string, config map[string]string) (string, error) {
    tempFile, err := os.CreateTemp("", "rclone-*.conf")
    if err != nil {
        return "", err
    }
    defer tempFile.Close()

    // Corrigir nome da seção para o nome real do remote
    content := fmt.Sprintf("[%s]\n", remoteName)
    for k, v := range config {
        content += fmt.Sprintf("%s = %s\n", k, v)
    }

    if _, err := tempFile.WriteString(content); err != nil {
        return "", err
    }
    return tempFile.Name(), nil
}
