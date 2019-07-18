/*
 * Copyright (c) 2015-2018 Nexenta Systems, Inc.
 *
 * This file is part of EdgeFS Project
 * (see https://github.com/Nexenta/edgefs).
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package efsutil

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
)

func GetMD5HashInt32(str string) uint32 {
	hasher := md5.New()
	hasher.Write([]byte(str))
	return binary.BigEndian.Uint32(hasher.Sum(nil))
}

func AppendStringToFile(fileName string, content string) error {
	f, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("Can't open file %s. %v", fileName, err)
	}
	if _, err = f.WriteString(content); err != nil {
		return fmt.Errorf("Can't write to file %s. %v", fileName, err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("Can't close file %s. %v", fileName, err)
	}

	return nil
}

func CopyFile(sourceFile string, destinationFile string) error {
	cpCmd := exec.Command("cp", "-rf", sourceFile, destinationFile)
	return cpCmd.Run()
}

func ReplaceInFile(fileName string, pattern string, value string) error {
	f, err := os.Open(fileName)
	if err != nil {
		return fmt.Errorf("Can't open file %s. %v", fileName, err)
	}
	r, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("Can't compile regex by pattern %s. %v", pattern, err)
	}

	byteValue, _ := ioutil.ReadAll(f)
	output := r.ReplaceAll(byteValue, []byte(value))

	defer f.Close()

	err = ioutil.WriteFile(fileName, []byte(output), 0644)
	if err != nil {
		return fmt.Errorf("Can't write update to file %s. %v", fileName, err)
	}

	return nil
}

func MarshalToFile(path string, data interface{}) error {
	json, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return fmt.Errorf("Can't marshall file %s. %v", path, err)
	}
	err = ioutil.WriteFile(path, json, 0644)
	if err != nil {
		return fmt.Errorf("Can't write to file %s. %v", path, err)
	}
	return nil
}

func LoadJsonFile(obj interface{}, fileName string) error {
	jsonFile, err := os.Open(fileName)

	if err != nil {
		return fmt.Errorf("Can't open json file %s. %v", fileName, err)
	}

	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)

	err = json.Unmarshal(byteValue, obj)
	if err != nil {
		return fmt.Errorf("Error unmarshalling JSON file %s %v", fileName, err)
	}

	return nil
}

func IsDirectory(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}

	if fi.Mode().IsDir() {
		return true
	}

	return false
}

func GetFolderContent(path string) ([]os.FileInfo, error) {

	files, err := ioutil.ReadDir(path)
	if err != nil {
		return nil, err
	}

	return files, nil
}
