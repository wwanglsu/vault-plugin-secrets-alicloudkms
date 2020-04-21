package alicloudkms

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/hashicorp/errwrap"
	"os"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
	// "github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	// kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

func (b *backend) pathDecrypt() *framework.Path {
	fmt.Println("This is test on 4/16/2020-alicloudkms pathDecrypt()")
	return &framework.Path{
		Pattern: "decrypt/" + framework.GenericNameRegex("key"),

		HelpSynopsis: "Decrypt a ciphertext value using a named key",
		HelpDescription: `
Use the named encryption key to decrypt a ciphertext string previously
encrypted with this same key. The provided ciphertext come from a previous
invocation of the /encrypt endpoint. It is not guaranteed to work with values
encrypted with the same Google Cloud KMS key outside of Vault.
`,

		Fields: map[string]*framework.FieldSchema{
			"key": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `
Name of the key in Vault to use for decryption. This key must already exist in
Vault and must map back to a Google Cloud KMS key.
`,
			},

			"additional_authenticated_data": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `
Optional data that was specified during encryption of this payload.
`,
			},

			"ciphertext": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `
Ciphertext to decrypt as previously returned from an encrypt operation. This
must be base64-encoded ciphertext as previously returned from an encrypt
operation.
`,
			},

			"key_version": &framework.FieldSchema{
				Type: framework.TypeInt,
				Description: `
Integer version of the crypto key version to use for decryption. This is
required for asymmetric keys. For symmetric keys, Cloud KMS will choose the
correct version automatically.
`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: withFieldValidator(b.pathDecryptWrite),
			logical.UpdateOperation: withFieldValidator(b.pathDecryptWrite),
		},
	}
}

// pathDecryptWrite corresponds to PUT/POST alicloudkms/decrypt/:key and is
// used to decrypt the ciphertext string using the named key.
func (b *backend) pathDecryptWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	fmt.Println("This is test on 4/16/2020-alicloudkms pathDecryptWrite()")
	// key := d.Get("key").(string)
	ciphertext := d.Get("ciphertext").(string)
	// aad := d.Get("additional_authenticated_data").(string)
	// keyVersion := d.Get("key_version").(int)

	/*k, err := b.Key(ctx, req.Storage, key)
	if err != nil {
		if err == ErrKeyNotFound {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
		return nil, err
	}*/

	// We gave the user back base64-encoded ciphertext in the /encrypt payload
	/*ciphertext, err := base64.StdEncoding.DecodeString(d.Get("ciphertext").(string))
	if err != nil {
		return nil, errwrap.Wrapf("failed to base64 decode ciphtertext: {{err}}", err)
	}*/

	/*cryptoKey := k.CryptoKeyID
	if keyVersion > 0 {
		if k.MinVersion > 0 && keyVersion < k.MinVersion {
			resp := fmt.Sprintf("requested version %d is less than minimum allowed version of %d",
				keyVersion, k.MinVersion)
			return logical.ErrorResponse(resp), logical.ErrPermissionDenied
		}

		if k.MaxVersion > 0 && keyVersion > k.MaxVersion {
			resp := fmt.Sprintf("requested version %d is greater than maximum allowed version of %d",
				keyVersion, k.MaxVersion)
			return logical.ErrorResponse(resp), logical.ErrPermissionDenied
		}

		cryptoKey = fmt.Sprintf("%s/cryptoKeyVersions/%d", cryptoKey, keyVersion)
	}*/

	/*kmsClient, closer, err := b.KMSClient(req.Storage)
	if err != nil {
		return nil, err
	}
	defer closer()*/

	// Lookup the key so we can determine the type of decryption (symmetric or
	// asymmetric).
	/*ck, err := kmsClient.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{
		Name: k.CryptoKeyID,
	})
	if err != nil {
		return nil, errwrap.Wrapf("failed to get underlying crypto key: {{err}}", err)
	}*/

	ciphertextBlob, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, errwrap.Wrapf("failed to base64 decode ciphtertext: {{err}}", err)
	}

	var plaintext string

	accessKeyId := os.Getenv("ALICLOUD_ACCESS_KEY_ID")
	accessKeySecret := os.Getenv("ALICLOUD_SECRET_ACCESS_KEY")
	client, err := kms.NewClientWithAccessKey("cn-hangzhou", accessKeyId, accessKeySecret)
	if err != nil{
		fmt.Println("Got error in initialize AliCloud KMS Client: ", err)
	}

	client.GetConfig().Scheme="HTTPS"

	decryReq:=kms.DecryptRequest{
		RpcRequest:              &requests.RpcRequest{},
		CiphertextBlob:          string(ciphertextBlob),
	}
	decryReq.InitWithApiInfo("Kms", "2016-01-20", "Decrypt", "kms", "openAPI")
	decResp,err := client.Decrypt(&decryReq)
	if err !=nil{
		fmt.Println("Got error in AliCloud KMS decrypting: ", err)
	}
	plaintext = decResp.Plaintext
	fmt.Println("AliCloud KMS Decrypted string: ", plaintext)


	/*switch ck.Purpose {
	case kmspb.CryptoKey_ASYMMETRIC_DECRYPT:
		if keyVersion == 0 {
			return nil, errMissingFields("key_version")
		}

		resp, err := kmsClient.AsymmetricDecrypt(ctx, &kmspb.AsymmetricDecryptRequest{
			Name:       cryptoKey,
			Ciphertext: ciphertext,
		})
		if err != nil {
			return nil, errwrap.Wrapf("failed to decrypt ciphertext (asymmetric): {{err}}", err)
		}
		plaintext = string(resp.Plaintext)
	case kmspb.CryptoKey_ENCRYPT_DECRYPT, kmspb.CryptoKey_CRYPTO_KEY_PURPOSE_UNSPECIFIED:
		resp, err := kmsClient.Decrypt(ctx, &kmspb.DecryptRequest{
			Name:                        cryptoKey,
			Ciphertext:                  ciphertext,
			AdditionalAuthenticatedData: []byte(aad),
		})
		if err != nil {
			return nil, errwrap.Wrapf("failed to decrypt ciphertext (symmetric): {{err}}", err)
		}
		plaintext = string(resp.Plaintext)
	case kmspb.CryptoKey_ASYMMETRIC_SIGN:
		return nil, logical.ErrUnsupportedOperation
	}*/

	return &logical.Response{
		Data: map[string]interface{}{
			"plaintext": plaintext,
		},
	}, nil
}
