/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/core/crypto/primitives"
	"github.com/op/go-logging"
)

var myLogger = logging.MustGetLogger("asset_mgm")

// AssetManagementChaincode is simple chaincode implementing a basic Asset Management system
// with access control enforcement at chaincode level.
// Look here for more information on how to implement access control at chaincode level:
// https://github.com/hyperledger/fabric/blob/master/docs/tech/application-ACL.md
// An asset is simply represented by a string.
type AssetManagementChaincode struct {
}

// Init method will be called during deployment.
// The deploy transaction metadata is supposed to contain the administrator cert
func (t *AssetManagementChaincode) Init(stub *shim.ChaincodeStub, function string, args []string) ([]byte, error) {
	myLogger.Debug("Init Chaincode...")
	if len(args) != 0 {
		return nil, errors.New("Incorrect number of arguments. Expecting 0")
	}

	// Create ownership table
	err := stub.CreateTable("AssetsOwnership", []*shim.ColumnDefinition{
		&shim.ColumnDefinition{Name: "Asset", Type: shim.ColumnDefinition_STRING, Key: true},
		&shim.ColumnDefinition{Name: "Owner", Type: shim.ColumnDefinition_BYTES, Key: false},
	})
	if err != nil {
		return nil, errors.New("Failed creating AssetsOnwership table.")
	}

	// Create SupplierDirectory table
	err = stub.CreateTable("SupplierDirectory", []*shim.ColumnDefinition{
		&shim.ColumnDefinition{Name: "SupplierID", Type: shim.ColumnDefinition_STRING, Key: true},
		&shim.ColumnDefinition{Name: "MetaData", Type: shim.ColumnDefinition_STRING, Key: false},
	})
	if err != nil {
		return nil, errors.New("Failed creating SupplierDirectory table.")
	}

	// Create BuyerDirectory table
	err = stub.CreateTable("BuyerDirectory", []*shim.ColumnDefinition{
		&shim.ColumnDefinition{Name: "BuyerID", Type: shim.ColumnDefinition_STRING, Key: true},
		&shim.ColumnDefinition{Name: "MetaData", Type: shim.ColumnDefinition_STRING, Key: false},
	})
	if err != nil {
		return nil, errors.New("Failed creating BuyerDirectory table.")
	}

	// Create FunderDirectory table
	err = stub.CreateTable("FunderDirectory", []*shim.ColumnDefinition{
		&shim.ColumnDefinition{Name: "FunderID", Type: shim.ColumnDefinition_STRING, Key: true},
		&shim.ColumnDefinition{Name: "MetaData", Type: shim.ColumnDefinition_STRING, Key: false},
		&shim.ColumnDefinition{Name: "Criteria", Type: shim.ColumnDefinition_STRING, Key: false},
	})
	if err != nil {
		return nil, errors.New("Failed creating FunderDirectory table.")
	}

	// Create FundingOperations table
	err = stub.CreateTable("FundingOperations", []*shim.ColumnDefinition{
		&shim.ColumnDefinition{Name: "OperationID", Type: shim.ColumnDefinition_STRING, Key: true},
		&shim.ColumnDefinition{Name: "MetaData", Type: shim.ColumnDefinition_STRING, Key: false},
		&shim.ColumnDefinition{Name: "Status", Type: shim.ColumnDefinition_INT32, Key: false},
	})
	if err != nil {
		return nil, errors.New("Failed creating FunderDirectory table.")
	}

	// Set the admin
	// The metadata will contain the certificate of the administrator
	//adminCert, err := stub.GetCallerMetadata()
	//if err != nil {
	//	myLogger.Debug("Failed getting metadata")
	//	return nil, errors.New("Failed getting metadata.")
	//}
	//if len(adminCert) == 0 {
	//	myLogger.Debug("Invalid admin certificate. Empty.")
	//	return nil, errors.New("Invalid admin certificate. Empty.")
	//}
	//
	//myLogger.Debug("The administrator is [%x]", adminCert)
	//
	//stub.PutState("admin", adminCert)

	myLogger.Debug("Init Chaincode...done")

	return nil, nil
}

func (t *AssetManagementChaincode) assign(stub *shim.ChaincodeStub, args []string) ([]byte, error) {
	myLogger.Debug("Assign...")

	if len(args) != 2 {
		return nil, errors.New("Incorrect number of arguments. Expecting 2")
	}

	asset := args[0]
	owner, err := base64.StdEncoding.DecodeString(args[1])
	if err != nil {
		return nil, errors.New("Failed decodinf owner")
	}

	// Verify the identity of the caller
	// Only an administrator can invoker assign
	adminCertificate, err := stub.GetState("admin")
	if err != nil {
		return nil, errors.New("Failed fetching admin identity")
	}

	ok, err := t.isCaller(stub, adminCertificate)
	if err != nil {
		return nil, errors.New("Failed checking admin identity")
	}
	if !ok {
		return nil, errors.New("The caller is not an administrator")
	}

	// Register assignment
	myLogger.Debugf("New owner of [%s] is [% x]", asset, owner)

	ok, err = stub.InsertRow("AssetsOwnership", shim.Row{
		Columns: []*shim.Column{
			&shim.Column{Value: &shim.Column_String_{String_: asset}},
			&shim.Column{Value: &shim.Column_Bytes{Bytes: owner}}},
	})

	if !ok && err == nil {
		return nil, errors.New("Asset was already assigned.")
	}

	myLogger.Debug("Assign...done!")

	return nil, err
}

func (t *AssetManagementChaincode) transfer(stub *shim.ChaincodeStub, args []string) ([]byte, error) {
	myLogger.Debug("Transfer...")

	if len(args) != 2 {
		return nil, errors.New("Incorrect number of arguments. Expecting 2")
	}

	asset := args[0]
	newOwner, err := base64.StdEncoding.DecodeString(args[1])
	if err != nil {
		return nil, fmt.Errorf("Failed decoding owner")
	}

	// Verify the identity of the caller
	// Only the owner can transfer one of his assets
	var columns []shim.Column
	col1 := shim.Column{Value: &shim.Column_String_{String_: asset}}
	columns = append(columns, col1)

	row, err := stub.GetRow("AssetsOwnership", columns)
	if err != nil {
		return nil, fmt.Errorf("Failed retrieving asset [%s]: [%s]", asset, err)
	}

	prvOwner := row.Columns[1].GetBytes()
	myLogger.Debugf("Previous owener of [%s] is [% x]", asset, prvOwner)
	if len(prvOwner) == 0 {
		return nil, fmt.Errorf("Invalid previous owner. Nil")
	}

	// Verify ownership
	ok, err := t.isCaller(stub, prvOwner)
	if err != nil {
		return nil, errors.New("Failed checking asset owner identity")
	}
	if !ok {
		return nil, errors.New("The caller is not the owner of the asset")
	}

	// At this point, the proof of ownership is valid, then register transfer
	err = stub.DeleteRow(
		"AssetsOwnership",
		[]shim.Column{shim.Column{Value: &shim.Column_String_{String_: asset}}},
	)
	if err != nil {
		return nil, errors.New("Failed deliting row.")
	}

	_, err = stub.InsertRow(
		"AssetsOwnership",
		shim.Row{
			Columns: []*shim.Column{
				&shim.Column{Value: &shim.Column_String_{String_: asset}},
				&shim.Column{Value: &shim.Column_Bytes{Bytes: newOwner}},
			},
		})
	if err != nil {
		return nil, errors.New("Failed inserting row.")
	}

	myLogger.Debug("New owner of [%s] is [% x]", asset, newOwner)

	myLogger.Debug("Transfer...done")

	return nil, nil
}

func (t *AssetManagementChaincode) createSupplier(stub *shim.ChaincodeStub, args []string) ([]byte, error) {
	myLogger.Debug("Create Supplier...")

	if len(args) != 2 {
		return nil, errors.New("Incorrect number of arguments. Expecting 2")
	}

	// Metadata for describing basic information of supplier, like industry type, sensitive data hashed with salt
	uuid := args[0]
	metaData := args[1]

	// Verify the identity of the caller
	// Only an administrator can
	//adminCertificate, err := stub.GetState("admin")
	//if err != nil {
	//	return nil, errors.New("Failed fetching admin identity")
	//}
	//
	//ok, err := t.isCaller(stub, adminCertificate)
	//if err != nil {
	//	return nil, errors.New("Failed checking admin identity")
	//}
	//if !ok {
	//	return nil, errors.New("The caller is not an administrator")
	//}

	_, err := stub.InsertRow(
		"SupplierDirectory",
		shim.Row{
			Columns: []*shim.Column{
				&shim.Column{Value: &shim.Column_String_{String_: uuid}},
				&shim.Column{Value: &shim.Column_String_{String_: metaData}},
			},
		})
	if err != nil {
		return nil, errors.New("Failed inserting row.")
	}

	myLogger.Debug("Create Supplier...done")

	return nil, nil
}

func (t *AssetManagementChaincode) updateSupplier(stub *shim.ChaincodeStub, args []string) ([]byte, error) {
	myLogger.Debug("Update Supplier...")

	if len(args) != 2 {
		return nil, errors.New("Incorrect number of arguments. Expecting 2")
	}

	uuid := args[0]
	metaData := args[1]

	// Verify the identity of the caller
	// Only an administrator can
	//adminCertificate, err := stub.GetState("admin")
	//if err != nil {
	//	return nil, errors.New("Failed fetching admin identity")
	//}
	//
	//ok, err := t.isCaller(stub, adminCertificate)
	//if err != nil {
	//	return nil, errors.New("Failed checking admin identity")
	//}
	//if !ok {
	//	return nil, errors.New("The caller is not an administrator")
	//}

	// At this point, the proof of ownership is valid, then update
	ok, err := stub.ReplaceRow(
		"SupplierDirectory",
		shim.Row{
			Columns: []*shim.Column{
				&shim.Column{Value: &shim.Column_String_{String_: uuid}},
				&shim.Column{Value: &shim.Column_String_{String_: metaData}},
			},
		})
	if err != nil {
		return nil, fmt.Errorf("Failed replacing row [%s]", err)
	}
	if !ok {
		return nil, errors.New("Failed replacing row.")
	}

	myLogger.Debug("Update Supplier...done")

	return nil, nil
}

func (t *AssetManagementChaincode) createBuyer(stub *shim.ChaincodeStub, args []string) ([]byte, error) {
	myLogger.Debug("Create Buyer...")

	if len(args) != 2 {
		return nil, errors.New("Incorrect number of arguments. Expecting 2")
	}

	// Metadata for describing basic information of buyer, sensitive data hashed with salt
	uuid := args[0]
	metaData := args[1]

	_, err := stub.InsertRow(
		"BuyerDirectory",
		shim.Row{
			Columns: []*shim.Column{
				&shim.Column{Value: &shim.Column_String_{String_: uuid}},
				&shim.Column{Value: &shim.Column_String_{String_: metaData}},
			},
		})
	if err != nil {
		return nil, errors.New("Failed inserting row.")
	}

	myLogger.Debug("Create Buyer...done")

	return nil, nil
}

func (t *AssetManagementChaincode) updateBuyer(stub *shim.ChaincodeStub, args []string) ([]byte, error) {
	myLogger.Debug("Update Buyer...")

	if len(args) != 2 {
		return nil, errors.New("Incorrect number of arguments. Expecting 2")
	}

	uuid := args[0]
	metaData := args[1]

	// At this point, the proof of ownership is valid, then update
	ok, err := stub.ReplaceRow(
		"BuyerDirectory",
		shim.Row{
			Columns: []*shim.Column{
				&shim.Column{Value: &shim.Column_String_{String_: uuid}},
				&shim.Column{Value: &shim.Column_String_{String_: metaData}},
			},
		})
	if err != nil {
		return nil, fmt.Errorf("Failed replacing row [%s]", err)
	}
	if !ok {
		return nil, errors.New("Failed replacing row.")
	}

	myLogger.Debug("Update Buyer...done")

	return nil, nil
}

func (t *AssetManagementChaincode) createFunder(stub *shim.ChaincodeStub, args []string) ([]byte, error) {
	myLogger.Debug("Create Funder...")

	if len(args) != 3 {
		return nil, errors.New("Incorrect number of arguments. Expecting 3")
	}

	// Metadata for describing basic information of funder, like industry type, sensitive data hashed with salt
	// Criteria for approving funding requests (funding operations) - hashaed with salt.
	uuid := args[0]
	metaData := args[1]
	criteria := args[2]

	_, err := stub.InsertRow(
		"FunderDirectory",
		shim.Row{
			Columns: []*shim.Column{
				&shim.Column{Value: &shim.Column_String_{String_: uuid}},
				&shim.Column{Value: &shim.Column_String_{String_: metaData}},
				&shim.Column{Value: &shim.Column_String_{String_: criteria}},
			},
		})
	if err != nil {
		return nil, errors.New("Failed inserting row.")
	}

	myLogger.Debug("Create Funder...done")

	return nil, nil
}

func (t *AssetManagementChaincode) updateFunder(stub *shim.ChaincodeStub, args []string) ([]byte, error) {
	myLogger.Debug("Update Funder...")

	if len(args) != 3 {
		return nil, errors.New("Incorrect number of arguments. Expecting 3")
	}

	uuid := args[0]
	metaData := args[1]
	criteria := args[2]

	// At this point, the proof of ownership is valid, then update
	ok, err := stub.ReplaceRow(
		"FunderDirectory",
		shim.Row{
			Columns: []*shim.Column{
				&shim.Column{Value: &shim.Column_String_{String_: uuid}},
				&shim.Column{Value: &shim.Column_String_{String_: metaData}},
				&shim.Column{Value: &shim.Column_String_{String_: criteria}},
			},
		})
	if err != nil {
		return nil, fmt.Errorf("Failed replacing row [%s]", err)
	}
	if !ok {
		return nil, errors.New("Failed replacing row.")
	}

	myLogger.Debug("Update Funder...done")

	return nil, nil
}

func (t *AssetManagementChaincode) createOperation(stub *shim.ChaincodeStub, args []string) ([]byte, error) {
	myLogger.Debug("Create Operation...")

	if len(args) != 2 {
		return nil, errors.New("Incorrect number of arguments. Expecting 2")
	}

	// Metadata of operation
	uuid := args[0]
	metaData := args[1]
	status := int32(0)

	_, err := stub.InsertRow(
		"FundingOperations",
		shim.Row{
			Columns: []*shim.Column{
				&shim.Column{Value: &shim.Column_String_{String_: uuid}},
				&shim.Column{Value: &shim.Column_String_{String_: metaData}},
				&shim.Column{Value: &shim.Column_Int32{Int32: status}},
			},
		})
	if err != nil {
		return nil, errors.New("Failed inserting row.")
	}

	myLogger.Debug("Create Operation...done")

	return nil, nil
}

func (t *AssetManagementChaincode) updateOperation(stub *shim.ChaincodeStub, args []string) ([]byte, error) {
	myLogger.Debug("Update Operation...")

	if len(args) != 3 {
		return nil, errors.New("Incorrect number of arguments. Expecting 3")
	}

	uuid := args[0]
	metaData := args[1]
	statusStr := args[2]
	// need convert string to int32
	i, _ := strconv.ParseInt(statusStr, 0, 32)
	status := int32(i)

	// At this point, the proof of ownership is valid, then update
	ok, err := stub.ReplaceRow(
		"FundingOperations",
		shim.Row{
			Columns: []*shim.Column{
				&shim.Column{Value: &shim.Column_String_{String_: uuid}},
				&shim.Column{Value: &shim.Column_String_{String_: metaData}},
				&shim.Column{Value: &shim.Column_Int32{Int32: status}},
			},
		})
	if err != nil {
		return nil, fmt.Errorf("Failed replacing row [%s]", err)
	}
	if !ok {
		return nil, errors.New("Failed replacing row.")
	}

	myLogger.Debug("Update Operation...done")

	return nil, nil
}

func (t *AssetManagementChaincode) isCaller(stub *shim.ChaincodeStub, certificate []byte) (bool, error) {
	myLogger.Debug("Check caller...")

	// In order to enforce access control, we require that the
	// metadata contains the signature under the signing key corresponding
	// to the verification key inside certificate of
	// the payload of the transaction (namely, function name and args) and
	// the transaction binding (to avoid copying attacks)

	// Verify \sigma=Sign(certificate.sk, tx.Payload||tx.Binding) against certificate.vk
	// \sigma is in the metadata

	sigma, err := stub.GetCallerMetadata()
	if err != nil {
		return false, errors.New("Failed getting metadata")
	}
	payload, err := stub.GetPayload()
	if err != nil {
		return false, errors.New("Failed getting payload")
	}
	binding, err := stub.GetBinding()
	if err != nil {
		return false, errors.New("Failed getting binding")
	}

	myLogger.Debugf("passed certificate [% x]", certificate)
	myLogger.Debugf("passed sigma [% x]", sigma)
	myLogger.Debugf("passed payload [% x]", payload)
	myLogger.Debugf("passed binding [% x]", binding)

	ok, err := stub.VerifySignature(
		certificate,
		sigma,
		append(payload, binding...),
	)
	if err != nil {
		myLogger.Errorf("Failed checking signature [%s]", err)
		return ok, err
	}
	if !ok {
		myLogger.Error("Invalid signature")
	}

	myLogger.Debug("Check caller...Verified!")

	return ok, err
}

// Invoke will be called for every transaction.
// Supported functions are the following:
// "assign(asset, owner)": to assign ownership of assets. An asset can be owned by a single entity.
// Only an administrator can call this function.
// "transfer(asset, newOwner)": to transfer the ownership of an asset. Only the owner of the specific
// asset can call this function.
// An asset is any string to identify it. An owner is representated by one of his ECert/TCert.
func (t *AssetManagementChaincode) Invoke(stub *shim.ChaincodeStub, function string, args []string) ([]byte, error) {

	// Handle different functions
	if function == "assign" {
		// Assign ownership
		return t.assign(stub, args)
	} else if function == "transfer" {
		// Transfer ownership
		return t.transfer(stub, args)
	} else if function == "createSupplier" {
		// create Supplier
		return t.createSupplier(stub, args)
	} else if function == "updateSupplier" {
		// update Supplier
		return t.updateSupplier(stub, args)
	} else if function == "createBuyer" {
		// create Buyer
		return t.createBuyer(stub, args)
	} else if function == "updateBuyer" {
		// update Buyer
		return t.updateBuyer(stub, args)
	} else if function == "createFunder" {
		// create Funder
		return t.createFunder(stub, args)
	} else if function == "updateFunder" {
		// update Funder
		return t.updateFunder(stub, args)
	} else if function == "createOperation" {
		// create Operation
		return t.createOperation(stub, args)
	} else if function == "updateOperation" {
		// update Operation
		return t.updateOperation(stub, args)
	}

	return nil, errors.New("Received unknown function invocation")
}

// Query callback representing the query of a chaincode
// Supported functions are the following:
// "query(asset)": returns the owner of the asset.
// Anyone can invoke this function.
func (t *AssetManagementChaincode) Query(stub *shim.ChaincodeStub, function string, args []string) ([]byte, error) {
	myLogger.Debugf("Query [%s]", function)

	if function != "query" {
		return nil, errors.New("Invalid query function name. Expecting \"query\"")
	}

	var err error

	if len(args) != 1 {
		myLogger.Debug("Incorrect number of arguments. Expecting name of an asset to query")
		return nil, errors.New("Incorrect number of arguments. Expecting name of an asset to query")
	}

	// Who is the owner of the asset?
	asset := args[0]

	myLogger.Debugf("Arg [%s]", string(asset))

	var columns []shim.Column
	col1 := shim.Column{Value: &shim.Column_String_{String_: asset}}
	columns = append(columns, col1)

	row, err := stub.GetRow("AssetsOwnership", columns)
	if err != nil {
		myLogger.Debugf("Failed retriving asset [%s]: [%s]", string(asset), err)
		return nil, fmt.Errorf("Failed retriving asset [%s]: [%s]", string(asset), err)
	}

	myLogger.Debugf("Query done [% x]", row.Columns[1].GetBytes())

	return row.Columns[1].GetBytes(), nil
}

func main() {
	primitives.SetSecurityLevel("SHA3", 256)
	err := shim.Start(new(AssetManagementChaincode))
	if err != nil {
		fmt.Printf("Error starting AssetManagementChaincode: %s", err)
	}
}


