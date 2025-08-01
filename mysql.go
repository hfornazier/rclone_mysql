// ===============================================================
// Project:   MySQL Encrypted Backup Tool
// Package mysql is a custom rclone command for encrypted MySQL backup.
//
// Based on rclone (https://rclone.org/), created by Nick Craig-Wood and contributors.
//
// File:      mysql.go
// Version:   1.0.4
// Author: Humberto Fornazier (Brazil)
// mail:      jhfornazier@gmail.com
// License:   MIT License
// Created:   2025-08-01
// Updated:   2025-08-01
//
// Description:
// Implements a custom rclone command for encrypted MySQL backup,
// with the option to compress and upload to the cloud.
// The configuration is encrypted using a key derived from the system
// environment (hostname, user, path, OS). This ensures that backups
// can only be decrypted on the same machine.
// ===============================================================

package mysql

import (
    "archive/zip"
    "bufio"
    "context"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "crypto/tls"
    "database/sql"
    "encoding/hex"
    "fmt"
    "io"
    "net"
    "net/smtp"
    "os"
    "os/exec"
    "path/filepath"
    "runtime"
    "strings"
    "time"
    "bytes"

    "github.com/rclone/rclone/cmd"
    "github.com/rclone/rclone/fs/config/flags"
    "github.com/spf13/cobra"
    "github.com/dustin/go-humanize"
    _ "github.com/go-sql-driver/mysql"
)

// --- Constants and Global Variables ---
var (
    startTime     time.Time 
    criptFlag        bool   // --crip: encrypt config
    zipFlag          bool   // --zip: compress backup to ZIP
	logFlag          bool
    versionFlag      bool   // Script Version	
    listConfigFlag   bool // --list-config: list backups and remotes
    emailSucessoFlag bool // --emailsucess
    emailErroFlag    bool // --emailerr    
    databaseFlag     string // --database: DB section to use    
    rcloneBin        string
    mysqldumpBin     string    
    remoteFlag       string // --remote: target remote (e.g. drive:backups)            
    currentLogFile   string // guarda nome do log atual  
)

// --- Command Definition ---
const mysqlVersion = "v1.0.4" 

// commandDefinition registers the 'rclone mysql' command
var commandDefinition = &cobra.Command{
    Use:   "mysql",
    Short: "MySQL backup with encryption and upload to cloud",
    Run: func(command *cobra.Command, args []string) {
        if versionFlag {
            fmt.Printf("MySQL Backup Plugin %s\n", mysqlVersion)
            fmt.Printf("rclone mysql - rclone mysql - Plugin for backup of mysql databases\n")
            return
        }
        if criptFlag {
            handleEncryption(args)
            return
        }
        if listConfigFlag {
            listConfigs()
            return
        }        
        handleBackup()
    },
}

// init registers the command and its flags
func init() {
    cmd.Root.AddCommand(commandDefinition)
    cmdFlags := commandDefinition.Flags()
    flags.BoolVarP(cmdFlags, &criptFlag, "crip", "", false, "Encrypt configuration file", "")
    flags.StringVarP(cmdFlags, &databaseFlag, "database", "d", "", "Database section name", "")
    flags.BoolVarP(cmdFlags, &zipFlag, "zip", "z", false, "Compress backup into ZIP", "")
    flags.StringVarP(cmdFlags, &remoteFlag, "remote", "r", "", "Remote destination (e.g. 'drive:backups')", "")
    flags.BoolVarP(cmdFlags, &versionFlag, "mysqlversion", "", false, "version MySQL Plugin", "") 
	flags.BoolVarP(cmdFlags, &logFlag, "log", "", false, "Enable mysqldump log file", "")
    flags.BoolVarP(cmdFlags, &listConfigFlag, "list-config", "", false, "List configured backups and remotes", "MySQL")   
    flags.BoolVarP(cmdFlags, &emailSucessoFlag, "emailsucess", "", false, "Enviar e-mail em caso de sucesso", "")
    flags.BoolVarP(cmdFlags, &emailErroFlag, "emailerr", "", false, "Enviar e-mail em caso de erro", "")
}

// --- Main Functions ---

// handleEncryption encrypts a plain config.txt into rclone-config.enc
func handleEncryption(args []string) {
	
    if len(args) == 0 {
        fmt.Println("Error: Provide configuration file")
        fmt.Println("Example: ./rclone mysql --crip config.txt")
        return
    }
    if err := encryptFile(args[0], "rclone-config.enc"); err != nil {
        fmt.Printf("Encryption error: %v\n", err)
    } else {
        fmt.Println("Encrypted configuration saved to: rclone-config.enc")
    }
}

// handleBackup executes the full backup process
func handleBackup() {	

	initLog(databaseFlag) //Inicializa o log vazio   
	
	logStep("[INFO] ===== Starting backup process =====")
	logStep(fmt.Sprintf("[INFO] Database selected: %s", databaseFlag))

	if databaseFlag == "" {
		logStep("[ERROR] No database specified (--database)")
		fmt.Println("Error: Specify database with --database")
		return
	}

	content, err := decryptFile("rclone-config.enc")
	if err != nil {
		logStep(fmt.Sprintf("[ERROR] Decryption failed: %v", err))
		fmt.Printf("Decryption error: %v\n", err)
		return
	}
	logStep("[INFO] Configuration decrypted successfully")

	databases, remotes, err := parseSections(content)
	if err != nil {
		logStep(fmt.Sprintf("[ERROR] Failed to parse configuration: %v", err))
		fmt.Printf("Config parsing error: %v\n", err)
		return
	}
	logStep("[INFO] Configuration parsed successfully")

	// Validate if it exists [general]
	general, ok := remotes["general"]
	if !ok {
		logStep("[ERROR] Missing [general] section in configuration")
		fmt.Println("Error: Missing [general] section in config")
		return
	}
	logStep("[INFO] Found [general] section")

	// Helper to resolve binaries
	resolveBin := func(basePath, exeName string) (string, error) {
		info, err := os.Stat(basePath)
		if err != nil {
			return "", fmt.Errorf("Invalid Path: %s", basePath)
		}
		if info.IsDir() {
			exePath := filepath.Join(basePath, exeName)
			if _, err := os.Stat(exePath); err == nil {
				return exePath, nil
			}
			exePath = filepath.Join(basePath, strings.TrimSuffix(exeName, ".exe"))
			if _, err := os.Stat(exePath); err == nil {
				return exePath, nil
			}
			return "", fmt.Errorf("%s not found in %s", exeName, basePath)
		}
		return basePath, nil
	}

	// Validate mysqldump_path
	if path, ok := general["mysqldump_path"]; ok {
		bin, err := resolveBin(path, "mysqldump.exe")
		if err != nil {
			logStep(fmt.Sprintf("[ERROR] mysqldump path invalid: %v", err))
			fmt.Println("Erro:", err)
			return
		}
		mysqldumpBin = bin
		logStep(fmt.Sprintf("[INFO] mysqldump found at: %s", bin))
	} else {
		logStep("[ERROR] Missing mysqldump_path in [general]")
		fmt.Println("Error: Missing mysqldump_path in [general]")
		return
	}

	// Validate rclone_path
	if path, ok := general["rclone_path"]; ok {
		bin, err := resolveBin(path, "rclone.exe")
		if err != nil {
			logStep(fmt.Sprintf("[ERROR] rclone path invalid: %v", err))
			fmt.Println("Erro:", err)
			return
		}
		rcloneBin = bin
		logStep(fmt.Sprintf("[INFO] rclone found at: %s", bin))
	} else {
		logStep("[ERROR] Missing rclone_path in [general]")
		fmt.Println("Error: Missing rclone_path in [general]")
		return
	}

	// Search DB credentials
	credentials, ok := databases[databaseFlag]
	if !ok {
		logStep(fmt.Sprintf("[ERROR] Database section '%s' not found", databaseFlag))
		fmt.Printf("Database section '%s' not found\n", databaseFlag)
		return
	}
	logStep(fmt.Sprintf("[INFO] Database section '%s' found", databaseFlag))

	// Validate credentials
	if err := validateCredentials(credentials); err != nil {
		logStep(fmt.Sprintf("[ERROR] Invalid credentials: %v", err))
		fmt.Println(err)
		return
	}
	logStep("[INFO] Credentials validated successfully")

	// Run backup
	logStep("[INFO] Starting backup execution")
	if err := executeBackup(credentials, remotes); err != nil {
		logStep(fmt.Sprintf("[ERROR] Backup process failed: %v", err))
		fmt.Printf("Backup error: %v\n", err)
	} else {
		logStep("[SUCCESS] Backup process completed successfully")
	}	

	conteudoLog, err := os.ReadFile(currentLogFile)
	if err != nil {
		fmt.Printf("[ERROR] Não foi possível ler log %s: %v\n", currentLogFile, err)
		return
	}
	logText := string(conteudoLog)
	temErro := strings.Contains(logText, "[ERROR]")

	// Busca configuração de e-mail
	var emailCfg map[string]string
	emailCfg, ok = remotes["email"]
	if !ok {
		emailCfg, ok = databases["email"]
	}

	// Envia conforme flags
	if emailSucessoFlag && !temErro {
		enviarEmail(emailCfg, fmt.Sprintf("[SUCESSO] Backup %s", databaseFlag), logText)
	}
	if emailErroFlag && temErro {
		enviarEmail(emailCfg, fmt.Sprintf("[ERRO] Backup %s", databaseFlag), logText)
	}
	
}

// --- Configuration Parsing ---
// parseSections parses the INI-style config into maps
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

            // Tweak: include [general] inside remotes
            if strings.HasPrefix(currentSection, "remote_") {
                remotes[currentSection] = make(map[string]string)
            } else if currentSection == "general" {
                remotes["general"] = make(map[string]string)
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
                } else if currentSection == "general" {
                    remotes["general"][key] = value
                } else {
                    databases[currentSection][key] = value
                }
            }
        }
    }
    return databases, remotes, scanner.Err()
}


// --- Encryption/Decryption ---
// encryptFile encrypts inputFile using a key derived from the system
func encryptFile(inputFile, outputFile string) error {
    data, err := os.ReadFile(inputFile)
    if err != nil {
        return fmt.Errorf("error reading file: %v", err)
    }

    key, err := getVolumeID()
    if err != nil {
        return fmt.Errorf("error getting volume ID: %v", err)
    }

    hash := sha256.Sum256([]byte(key))
    block, err := aes.NewCipher(hash[:32])
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
    return os.WriteFile(outputFile, ciphertext, 0644)
}

// decryptFile decrypts the file using the same system-derived key
func decryptFile(fileName string) (string, error) {
    data, err := os.ReadFile(fileName)
    if err != nil {
        return "", fmt.Errorf("error reading file: %v", err)
    }

    key, err := getVolumeID()
    if err != nil {
        return "", fmt.Errorf("error getting volume ID: %v", err)
    }

    hash := sha256.Sum256([]byte(key))
    block, err := aes.NewCipher(hash[:32])
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonceSize := gcm.NonceSize()
    if len(data) < nonceSize {
        return "", fmt.Errorf("invalid encrypted file")
    }

    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", fmt.Errorf("decryption failed â€” this file can only be used on this machine or disk")
    }

    return string(plaintext), nil
}

// getVolumeID generates a unique fingerprint of the system
func getVolumeID() (string, error) {
    hostname, _ := os.Hostname()
    wd, _ := os.Getwd()
    username := os.Getenv("USER")
    if runtime.GOOS == "windows" {
        username = os.Getenv("USERNAME")
    }
    raw := fmt.Sprintf("%s:%s:%s:%s", runtime.GOOS, hostname, username, wd)
    hash := sha256.Sum256([]byte(raw))
    return hex.EncodeToString(hash[:16]), nil
}

// --- Validation and Connection ---

// validateCredentials checks required fields
func validateCredentials(credentials map[string]string) error {
    logStep("[INFO] Validating database credentials")

    required := []string{"server", "port", "db", "user"}
    for _, field := range required {
        if credentials[field] == "" {
            logStep(fmt.Sprintf("[ERROR] Missing required field: '%s'", field))
            return fmt.Errorf("missing required field: '%s'", field)
        }
    }

    // pass can be empty, but must exist
    if _, ok := credentials["pass"]; !ok {
        logStep("[ERROR] Missing required field: 'pass'")
        return fmt.Errorf("missing required field: 'pass'")
    }

    logStep("[INFO] Database credentials validation passed")
    return nil
}


// connectToMySQL tests the database connection
func connectToMySQL(credentials map[string]string) (*sql.DB, error) {
    logStep("[INFO] Testing MySQL connection")

    dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s",
        credentials["user"],
        credentials["pass"],
        credentials["server"],
        credentials["port"],
        credentials["db"],
    )

    db, err := sql.Open("mysql", dsn)
    if err != nil {
        logStep(fmt.Sprintf("[ERROR] Failed to initialize MySQL connection: %v", err))
        return nil, fmt.Errorf("failed to connect to MySQL: %v", err)
    }

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    if err := db.PingContext(ctx); err != nil {
        logStep(fmt.Sprintf("[ERROR] MySQL connection check failed: %v", err))
        return nil, fmt.Errorf("connection check failed: %v", err)
    }

    logStep("[INFO] MySQL connection successful")
    return db, nil
}


// --- Backup Execution ---
// executeBackup orchestrates the full backup process
func executeBackup(credentials map[string]string, remotes map[string]map[string]string) error {
    startTime = time.Now()
    logStep("[INFO] Starting backup process")

    // Test MySQL connection
    db, err := connectToMySQL(credentials)
    if err != nil {
        logStep(fmt.Sprintf("[ERROR] Backup aborted - MySQL connection failed: %v", err))
        return err
    }
    defer db.Close()

    // Create SQL dump
    logStep("[INFO] Starting mysqldump")
    backupFile, err := createBackupFile(credentials)
    if err != nil {
        logStep(fmt.Sprintf("[ERROR] mysqldump failed: %v", err))
        return err
    }
    logStep(fmt.Sprintf("[INFO] mysqldump completed: %s", backupFile))

    // Get dump size
    fileInfo, _ := os.Stat(backupFile)
    logStep(fmt.Sprintf("[INFO] Backup size: %s", humanize.Bytes(uint64(fileInfo.Size()))))
    logStep(fmt.Sprintf("[INFO] Duration so far: %v", time.Since(startTime).Round(time.Second)))

    // Compress if enabled
    if zipFlag {
        logStep("[INFO] Starting compression")
        zippedFile, err := compressBackup(backupFile)
        if err != nil {
            logStep(fmt.Sprintf("[ERROR] Compression failed: %v", err))
            return err
        }
        backupFile = zippedFile
        logStep(fmt.Sprintf("[INFO] Compression completed: %s", backupFile))
    }

    // Upload if enabled
    if shouldUpload(credentials) {
        logStep(fmt.Sprintf("[INFO] Uploading file: %s", filepath.Base(backupFile)))
        if err := uploadBackup(backupFile, remotes); err != nil {
            logStep(fmt.Sprintf("[ERROR] Upload failed: %v", err))
            return err
        }
        logStep("[INFO] Upload completed successfully")
    }

    logStep(fmt.Sprintf("[SUCCESS] Backup finished successfully in %v", time.Since(startTime).Round(time.Second)))
    return nil
}



// createBackupFile runs mysqldump and saves the .sql file
func createBackupFile(credentials map[string]string) (string, error) {
    logStep("[INFO] Starting backup file creation")

    backupDir := "bbksql"
    if err := os.MkdirAll(backupDir, 0755); err != nil {
        logStep(fmt.Sprintf("[ERROR] Failed to create directory '%s': %v", backupDir, err))
        return "", fmt.Errorf("error creating directory: %v", err)
    }
        
    logStep(fmt.Sprintf("[INFO] Backup directory ready: %s", backupDir))

    timestamp := time.Now().Format("20060102_150405")
    fileName := filepath.Join(backupDir, fmt.Sprintf("%s_%s.sql", databaseFlag, timestamp))
    logStep(fmt.Sprintf("[INFO] Backup file will be: %s", fileName))

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
    defer cancel()

    args := []string{
        "-h", credentials["server"],
        "-P", credentials["port"],
        "-u", credentials["user"],
    }
    if credentials["pass"] != "" {
        args = append(args, fmt.Sprintf("-p%s", credentials["pass"]))
    }

    args = append(args,
        "--max-allowed-packet=268435456",
        "--single-transaction",
        "--quick",
        "--default-character-set=latin1",
        "--set-charset",
        "--complete-insert",
        "--skip-extended-insert",
    )

    if logFlag {
        args = append(args, "--verbose", "--log-error=backup.log")
    }

    args = append(args, credentials["db"])

    logStep(fmt.Sprintf("[INFO] Running mysqldump", args))

    cmd := exec.CommandContext(ctx, mysqldumpBin, args...)

    stderr, err := cmd.StderrPipe()
    if err != nil {
        logStep(fmt.Sprintf("[ERROR] Failed to attach stderr: %v", err))
        return "", err
    }

    outFile, err := os.Create(fileName)
    if err != nil {
        logStep(fmt.Sprintf("[ERROR] Failed to create SQL file: %v", err))
        return "", err
    }
    cmd.Stdout = outFile

    if err := cmd.Start(); err != nil {
        logStep(fmt.Sprintf("[ERROR] Failed to start mysqldump: %v", err))
        return "", fmt.Errorf("failed to start mysqldump: %v", err)
    }
    logStep("[INFO] mysqldump started successfully")

    done := make(chan bool)
    go func() {
        spinner := []string{"|", "/", "-", "\\"}
        i := 0
        for {
            select {
            case <-done:
                return
            default:
                fmt.Printf("\rRunning mysqldump %s", spinner[i%4])
                time.Sleep(100 * time.Millisecond)
                i++
            }
        }
    }()

    scanner := bufio.NewScanner(stderr)
    go func() {
        for scanner.Scan() {
            fmt.Printf("\r\033[K%s\n", scanner.Text())
        }
    }()

    if err := cmd.Wait(); err != nil {
        done <- true
        logStep(fmt.Sprintf("[ERROR] mysqldump finished with error: %v", err))
        return "", fmt.Errorf("mysqldump error: %v", err)
    }
    done <- true
    logStep("[INFO] mysqldump completed successfully")
    fmt.Printf("\r\033[Kmysqldump completed successfully!\n")

    fileInfo, _ := os.Stat(fileName)
    logStep(fmt.Sprintf("[INFO] Backup size: %s", humanize.Bytes(uint64(fileInfo.Size()))))
    logStep(fmt.Sprintf("[INFO] Total time: %v", time.Since(startTime).Round(time.Second)))

    fmt.Printf("\nBackup size: %s\n", humanize.Bytes(uint64(fileInfo.Size())))
    fmt.Printf("Total time: %v\n", time.Since(startTime).Round(time.Second))
    return fileName, nil
}


// --- Compression ---
// compressBackup compresses the .sql file into .zip and deletes the original
func compressBackup(sqlFile string) (string, error) {
    logStep("[INFO] Starting compression for file: %s", sqlFile)

    zipFile := strings.TrimSuffix(sqlFile, ".sql") + ".zip"

    // 1. Create the ZIP in a different temporary directory
    tmpZip := filepath.Join(os.TempDir(), filepath.Base(zipFile))
    zipWriter, err := os.Create(tmpZip)
    if err != nil {
        logStep("[ERROR] Failed to create temp ZIP: %v", err)
        return "", err
    }

    // 2. Use in-memory buffering to avoid locks
    var buf bytes.Buffer
    archive := zip.NewWriter(&buf)

    // 3. Read SQL contents completely before zipping
    sqlData, err := os.ReadFile(sqlFile)
    if err != nil {
        logStep("[ERROR] Failed to read SQL file for compression: %v", err)
        zipWriter.Close()
        os.Remove(tmpZip)
        return "", err
    }

    // 4. Add to ZIP directly from memory
    writer, err := archive.Create(filepath.Base(sqlFile))
    if err != nil {
        logStep("[ERROR] Failed to create file inside ZIP: %v", err)
        zipWriter.Close()
        os.Remove(tmpZip)
        return "", err
    }

    if _, err := writer.Write(sqlData); err != nil {
        logStep("[ERROR] Failed to write SQL data to ZIP: %v", err)
        archive.Close()
        zipWriter.Close()
        os.Remove(tmpZip)
        return "", err
    }

    // 5. Finalize the ZIP
    if err := archive.Close(); err != nil {
        logStep("[ERROR] Failed to finalize ZIP: %v", err)
        zipWriter.Close()
        os.Remove(tmpZip)
        return "", err
    }

    // 6. Write the complete ZIP to disk
    if _, err := io.Copy(zipWriter, &buf); err != nil {
        logStep("[ERROR] Failed to write ZIP to disk: %v", err)
        zipWriter.Close()
        os.Remove(tmpZip)
        return "", err
    }

    // 7. Close the ZIP file
    if err := zipWriter.Close(); err != nil {
        logStep("[ERROR] Failed to close ZIP file: %v", err)
        os.Remove(tmpZip)
        return "", err
    }

    // 8. Move the ZIP to the final destination
    if err := os.Rename(tmpZip, zipFile); err != nil {
        logStep("[ERROR] Failed to move ZIP to destination: %v", err)
        os.Remove(tmpZip)
        return "", err
    }
    logStep("[INFO] Compression completed: %s", zipFile)

    // 9. Remove SQL immediately after reading
    if err := os.Remove(sqlFile); err != nil {
        logStep("[WARN] Failed to remove original SQL file after compression: %v", err)
    } else {
        logStep("[INFO] Removed original SQL file: %s", sqlFile)
    }

    return zipFile, nil
}


// --- Upload Logic ---

// shouldUpload checks if upload is requested
func shouldUpload(credentials map[string]string) bool {
    return remoteFlag != "" || credentials["remote"] != ""
}

// uploadBackup handles the cloud upload
func uploadBackup(backupFile string, remotes map[string]map[string]string) error {
    logStep("[INFO] Preparing to upload backup file: %s", filepath.Base(backupFile))

    remoteToUse := getRemoteTarget()
    if remoteToUse == "" {
        remoteToUse = getDefaultRemote(remotes)
    }
    if remoteToUse == "" {
        logStep("[ERROR] No remote specified for upload")
        return fmt.Errorf("no remote specified")
    }
    logStep("[INFO] Remote selected: %s", remoteToUse)

    remoteConfig, err := getRemoteConfig(remoteToUse, remotes)
    if err != nil {
        logStep("[ERROR] Failed to load remote configuration: %v", err)
        return err
    }

    logStep("[INFO] Starting upload to %s", remoteToUse)
    fmt.Printf("📤 Sending to %s: %s\n", remoteToUse, filepath.Base(backupFile))

    err = executeRcloneUpload(backupFile, remoteToUse, remoteConfig)
    if err != nil {
        logStep("[ERROR] Upload failed: %v", err)
        return err
    }

    logStep("[INFO] Upload completed successfully to %s", remoteToUse)
    return nil
}


// getRemoteTarget returns the remote from flag
func getRemoteTarget() string {
    if remoteFlag != "" {
        return remoteFlag
    }
    return ""
}

// getDefaultRemote picks the first remote_ section
func getDefaultRemote(remotes map[string]map[string]string) string {
    for name := range remotes {
        if strings.HasPrefix(name, "remote_") {
            return strings.TrimPrefix(name, "remote_") + ":"
        }
    }
    return ""
}

// getRemoteConfig retrieves config for the target remote
func getRemoteConfig(remote string, remotes map[string]map[string]string) (map[string]string, error) {
    logStep("[INFO] Loading configuration for remote: %s", remote)

    parts := strings.SplitN(remote, ":", 2)
    remoteName := "remote_" + parts[0]
    config, exists := remotes[remoteName]
    if !exists {
        available := make([]string, 0, len(remotes))
        for k := range remotes {
            available = append(available, strings.TrimPrefix(k, "remote_"))
        }
        logStep("[ERROR] Remote '%s' not found. Available remotes: %v", parts[0], available)
        return nil, fmt.Errorf("remote '%s' not found. Available: %v", parts[0], available)
    }

    logStep("[INFO] Remote configuration for '%s' loaded successfully", parts[0])
    return config, nil
}


// executeRcloneUpload runs the rclone copy command
func executeRcloneUpload(backupFile, remoteDest string, config map[string]string) error {
    logStep("[INFO] Preparing upload of %s to %s", filepath.Base(backupFile), remoteDest)

    parts := strings.SplitN(remoteDest, ":", 2)
    remoteName := parts[0]
    tempConfig, err := createTempConfig(remoteName, config)
    if err != nil {
        logStep("[ERROR] Failed to create temp config for remote: %v", err)
        return err
    }
    defer os.Remove(tempConfig)

    ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
    defer cancel()

    cmd := exec.CommandContext(ctx, rcloneBin,
        "--config", tempConfig,
        "copyto",
        backupFile,
        remoteDest+"/"+filepath.Base(backupFile),
        "--progress",
    )

    logStep("[INFO] Starting rclone upload command")
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr

    if err := cmd.Run(); err != nil {
        logStep("[ERROR] Upload failed: %v", err)
        return err
    }

    logStep("[SUCCESS] Upload completed successfully to %s", remoteDest)
    return nil
}


// createTempConfig creates a temporary rclone.conf for upload
func createTempConfig(remoteName string, config map[string]string) (string, error) {
    tempFile, err := os.CreateTemp("", "rclone-*.conf")
    if err != nil {
        return "", err
    }
    defer tempFile.Close()

    content := fmt.Sprintf("[%s]\n", remoteName)
    for k, v := range config {
        content += fmt.Sprintf("%s = %s\n", k, v)
    }
    if _, err := tempFile.WriteString(content); err != nil {
        return "", err
    }
    return tempFile.Name(), nil
}

func listConfigs() {
    content, err := decryptFile("rclone-config.enc")
    if err != nil {
        fmt.Printf("Erro ao descriptografar configuração: %v\n", err)
        return
    }

    databases, remotes, err := parseSections(content)
    if err != nil {
        fmt.Printf("Erro lendo configuração: %v\n", err)
        return
    }

    // Backups configurados
    fmt.Println("\nBackups:")
    for name := range databases {
        if name != "general" && name != "email" {
            fmt.Printf(" - %s\n", name)
        }
    }

    // Remotos configurados
    fmt.Println("\nRemotes:")
    for name := range remotes {
        if strings.HasPrefix(name, "remote_") {
            fmt.Printf(" - %s\n", strings.TrimPrefix(name, "remote_"))
        }
    }

    // Configuração geral
    fmt.Println("\n[general]:")
    if generalConfig, ok := databases["general"]; ok {
        for k, v := range generalConfig {
            fmt.Printf(" %s = %s\n", k, v)
        }
    } else if generalConfig, ok := remotes["general"]; ok {
        for k, v := range generalConfig {
            fmt.Printf(" %s = %s\n", k, v)
        }
    } else {
        fmt.Println(" (Seção 'general' não encontrada)")
    }

    // Configuração de email (sem senha)
    fmt.Println("\n[email]:")
    if emailConfig, ok := databases["email"]; ok {
        for k, v := range emailConfig {
            if k != "smtp_pass" { // Pula senha
                fmt.Printf(" %s = %s\n", k, v)
            }
        }
    } else if emailConfig, ok := remotes["email"]; ok {
        for k, v := range emailConfig {
            if k != "smtp_pass" { // Pula senha
                fmt.Printf(" %s = %s\n", k, v)
            }
        }
    } else {
        fmt.Println(" (Seção 'email' não encontrada)")
    }
}

// Initializes the specific log for a database
func initLog(database string) {
    logDir := "logs"

    // Create logs folder if it doesn't exist
    if err := os.MkdirAll(logDir, 0755); err != nil {
        fmt.Printf("[ERROR] Failed to create log directory '%s': %v\n", logDir, err)
        return
    }

    // Sets the full path of the log
    // Initializes the specific log for a database
    currentLogFile = filepath.Join(logDir, fmt.Sprintf("backup_%s.log", database))
    
    // Creates/overwrites empty file
    os.WriteFile(currentLogFile, []byte(""), 0644)
    logStep("=== Starting new backup process for database: %s ===", database)
}

func logStep(format string, args ...interface{}) {
    msg := fmt.Sprintf(format, args...)
    f, err := os.OpenFile(currentLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        fmt.Println("ERRO AO ABRIR LOG: %v", err)
        return
    }
    defer f.Close()
    
    timestamp := time.Now().Format("2006-01-02 15:04:05")
    if _, err := f.WriteString(fmt.Sprintf("[%s] %s\n", timestamp, msg)); err != nil {
        fmt.Println("ERRO AO ESCREVER NO LOG: %v", err)
    }
}

func enviarEmail(cfg map[string]string, subject, body string) {
    if cfg == nil || len(cfg) == 0 {
        fmt.Println("[INFO] Section [email] not found, email will not be sent")
        return
    }

    server := cfg["smtp_server"]
    port := cfg["smtp_port"]
    user := cfg["smtp_user"]
    pass := cfg["smtp_pass"]
    from := cfg["from"]
    recipients := strings.Split(cfg["to"], ",")

    hostPort := net.JoinHostPort(server, port)
    tlsconfig := &tls.Config{
        InsecureSkipVerify: true,
        ServerName:         server,
    }

    var client *smtp.Client
    var err error

    // Detect connection mode based on port
    if port == "465" {
        // Direct TLS (SMTPS)
        conn, errTLS := tls.Dial("tcp", hostPort, tlsconfig)
        if errTLS != nil {
            fmt.Printf("[ERROR] Failed to connect to SMTP (Direct TLS): %v\n", errTLS)
            return
        }
        defer conn.Close()

        client, err = smtp.NewClient(conn, server)
        if err != nil {
            fmt.Printf("[ERROR] Failed to create SMTP client: %v\n", err)
            return
        }

    } else {
        // STARTTLS (port 587 or others)
        client, err = smtp.Dial(hostPort)
        if err != nil {
            fmt.Printf("[ERROR] Failed to connect to SMTP: %v\n", err)
            return
        }

        if ok, _ := client.Extension("STARTTLS"); ok {
            if err = client.StartTLS(tlsconfig); err != nil {
                fmt.Printf("[ERROR] Failed to start STARTTLS: %v\n", err)
                return
            }
        }
    }
    defer client.Quit()

    // Authentication
    auth := smtp.PlainAuth("", user, pass, server)
    if err = client.Auth(auth); err != nil {
        fmt.Printf("[ERROR] SMTP authentication failed: %v\n", err)
        return
    }

    // MAIL FROM
    if err = client.Mail(from); err != nil {
        fmt.Printf("[ERROR] MAIL FROM failed: %v\n", err)
        return
    }

    // RCPT TO
    for _, dest := range recipients {
        dest = strings.TrimSpace(dest)
        if dest != "" {
            if err = client.Rcpt(dest); err != nil {
                fmt.Printf("[ERROR] RCPT TO %s failed: %v\n", dest, err)
                return
            }
        }
    }

    // Body
    writer, err := client.Data()
    if err != nil {
        fmt.Printf("[ERROR] DATA command failed: %v\n", err)
        return
    }

    msg := fmt.Sprintf("Subject: %s\r\nFrom: %s\r\nTo: %s\r\n\r\n%s",
        subject, from, strings.Join(recipients, ","), body)

    _, err = writer.Write([]byte(msg))
    if err != nil {
        fmt.Printf("[ERROR] Failed to write email body: %v\n", err)
        return
    }
    writer.Close()

    fmt.Println("[INFO] Email sent successfully!")
}


