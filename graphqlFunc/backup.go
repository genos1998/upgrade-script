package graphqlfunc

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
	"upgradationScript/logger"
)

const bucketName = "dgraph-backup"

func BackupAndRestoreDgraph(dgraphUrl, restoreServiceUrl string) error {

	logger.Logger.Info("----------Backup&Restore Process Begin-------------------")

	s3Url, found := os.LookupEnv("S3_ENDPOINT_URL")
	if !found {
		return fmt.Errorf("envar S3_ENDPOINT_URL is not set")
	}

	if _, found := os.LookupEnv("AWS_ACCESS_KEY_ID"); !found {
		return fmt.Errorf("envar AWS_ACCESS_KEY_ID is not set")
	}

	if _, found = os.LookupEnv("AWS_SECRET_ACCESS_KEY"); !found {
		return fmt.Errorf("envar AWS_SECRET_ACCESS_KEY is not set")
	}

	if err := generateDgraphBkp(dgraphUrl); err != nil {
		return err
	}

	now := time.Now().UTC()
	unixTimestamp := now.Unix()
	formattedTime := now.Format("02-01-2006") + "-" + fmt.Sprint(unixTimestamp)
	fileName := fmt.Sprintf("bkp-%v.tar.gz", formattedTime)

	filePath := fmt.Sprintf("/app/scanResult/%s", fileName)

	if err := tarBkpFile("/app/dgraph/bkp", filePath); err != nil {
		return fmt.Errorf("tarBkpFile: error: %s", err.Error())
	}

	if err := uploadBkpFile(s3Url, fileName); err != nil {
		return fmt.Errorf("%s", err.Error())
	}

	return restoreTheBkpFileInDgraph(fileName, restoreServiceUrl)

}

func tarBkpFile(source, target string) error {

	// Create the output file
	outFile, err := os.Create(target)
	if err != nil {
		return fmt.Errorf("could not create target file: %v", err)
	}
	defer outFile.Close()

	// Create a gzip writer
	gzWriter := gzip.NewWriter(outFile)
	defer gzWriter.Close()

	// Create a tar writer
	tarWriter := tar.NewWriter(gzWriter)
	defer tarWriter.Close()

	// Walk through the source directory and add files to the tar
	err = filepath.Walk(source, func(fileName string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Get file header
		header, err := tar.FileInfoHeader(fi, fi.Name())
		if err != nil {
			return err
		}

		// Update the name to maintain directory structure
		header.Name, err = filepath.Rel(filepath.Dir(source), fileName)
		if err != nil {
			return err
		}

		// Write the header
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}

		// If it's a file, write its content
		if !fi.Mode().IsRegular() {
			return nil
		}
		file, err := os.Open(fileName)
		if err != nil {
			return err
		}
		defer file.Close()

		if _, err := io.Copy(tarWriter, file); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("error walking through source directory: %v", err)
	}

	return os.RemoveAll(source)

}

func uploadBkpFile(s3Url, fileName string) error {
	s3client, err := MakeS3Client(context.TODO(), s3Url)
	if err != nil {
		err = fmt.Errorf("uploadBkpFile: unable to make s3 client %s", err.Error())
		return err
	}

	key := s3client.MakeS3Key(bucketName, "backups", fileName)

	bkpPath := fmt.Sprintf("/app/scanResult/%s", fileName)
	bkpFile, err := os.Open(bkpPath)
	if err != nil {
		return fmt.Errorf("uploadBkpFile: unable to open bkp file %s", err.Error())
	}

	if err := s3client.upload(context.TODO(), bucketName, key, bkpFile); err != nil {
		return fmt.Errorf("uploadBkpFile: unable to upload bkp file %s error: %s", key, err.Error())
	}

	return os.Remove(bkpPath)
}

func restoreTheBkpFileInDgraph(fileName, restoreServiceUrl string) error {
	restoreApi := "/api/v1/restore"

	restoreUrl, err := url.JoinPath(restoreServiceUrl, restoreApi)
	if err != nil {
		return fmt.Errorf("restoreTheBkpFileInDgraph: error: %s", err.Error())
	}

	httpclient := &http.Client{}
	req, err := http.NewRequest(
		http.MethodGet,
		restoreUrl,
		nil,
	)
	if err != nil {
		return fmt.Errorf("restoreTheBkpFileInDgraph: NewRequest error: %s", err.Error())
	}

	query := req.URL.Query()
	query.Set("file", fileName)
	req.URL.RawQuery = query.Encode()

	resp, err := httpclient.Do(req)
	if err != nil {
		return fmt.Errorf("restoreTheBkpFileInDgraph: Do error: %s", err.Error())
	}

	if resp.StatusCode == http.StatusOK {
		logger.Logger.Info("----------Backup&Restore Process Completed-------------------")
		return nil
	}

	type HttpError struct {
		Error string `json:"error,omitempty"`
	}

	defer resp.Body.Close()
	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("restoreTheBkpFileInDgraph: ReadAll error: %s", err.Error())
	}

	var stdError HttpError
	if err := json.Unmarshal(responseBytes, &stdError); err != nil {
		return fmt.Errorf("restoreTheBkpFileInDgraph: Unmarshal error: %s", err.Error())
	}

	return fmt.Errorf("restoreTheBkpFileInDgraph: %s", stdError.Error)

}
