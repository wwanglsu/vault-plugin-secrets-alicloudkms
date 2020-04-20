package alicloudkms

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
	// "github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathEncrypt() *framework.Path {
	fmt.Println("This is test on 4/16/2020-alicloudkms pathEncrypt()")
	return &framework.Path{
		Pattern: "encrypt/" + framework.GenericNameRegex("key"),

		HelpSynopsis: "Encrypt a plaintext value using a named key",
		HelpDescription: `
Use the named encryption key to encrypt an arbitrary plaintext string. The
response will be the base64-encoded encrypted value (ciphertext).
`,

		Fields: map[string]*framework.FieldSchema{
			"key": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `
Name of the key in Vault to use for encryption. This key must already exist in
Vault and must map back to a Google Cloud KMS key.
`,
			},

			"additional_authenticated_data": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `
Optional base64-encoded data that, if specified, must also be provided to
decrypt this payload.
`,
			},

			"key_version": &framework.FieldSchema{
				Type: framework.TypeInt,
				Description: `
Integer version of the crypto key version to use for encryption. If unspecified,
this defaults to the latest active crypto key version.
`,
			},

			"plaintext": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `
Plaintext value to be encrypted. This can be a string or binary, but the size
is limited. See the Google Cloud KMS documentation for information on size
limitations by key types.
`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: withFieldValidator(b.pathEncryptWrite),
			logical.UpdateOperation: withFieldValidator(b.pathEncryptWrite),
		},
	}
}

// pathEncryptWrite corresponds to PUT/POST alicloudkms/encrypt/:key and is
// used to encrypt the plaintext string using the named key.
func (b *backend) pathEncryptWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	fmt.Println("This is test on 4/16/2020-alicloudkms pathEncryptWrite()")
	key := d.Get("key").(string)
	// fmt.Println("Encrypting using alicloudkms key: "+key)
	// aad := d.Get("additional_authenticated_data").(string)
	plaintext := d.Get("plaintext").(string)
	// keyVersion := d.Get("key_version").(int)

	/*k, err := b.Key(ctx, req.Storage, key)
	if err != nil {
		if err == ErrKeyNotFound {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
		return nil, err
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
	defer closer()

	resp, err := kmsClient.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:                        cryptoKey,
		Plaintext:                   []byte(plaintext),
		AdditionalAuthenticatedData: []byte(aad),
	})
	if err != nil {
		return nil, errwrap.Wrapf("failed to encrypt plaintext: {{err}}", err)
	}*/

	client, err := kms.NewClientWithAccessKey("cn-hangzhou","LTAI4G5VKQ3n4QJ2vBFoR8rL","KS3exBiXnS8XFEtJvY47Juh0jIl2Yf")
	if err != nil{
		fmt.Println("Got error in creating AliCloud kms client: ", err)
	}

	client.GetConfig().Scheme="HTTPS"

	encryptReq := kms.EncryptRequest{
		RpcRequest:              &requests.RpcRequest{},
		KeyId: key,
		Plaintext: plaintext,
	}
	encryptReq.InitWithApiInfo("Kms", "2016-01-20", "Encrypt", "kms", "openAPI")

	encryresp, err := client.Encrypt(&encryptReq)
	if err !=nil{
		fmt.Println("Got error encrypting key: ", err)
	}
	fmt.Println("AliCloud Encrypted: ",encryresp.CiphertextBlob)
	base64 := base64.StdEncoding.EncodeToString([]byte(encryresp.CiphertextBlob))
	fmt.Println("base64 encoded string: ", base64)

	arn := "acs:kms:us-west-1:5803487320071979:key/" + key

	return &logical.Response{
		Data: map[string]interface{}{
			"arn": arn,
			"ciphertext":  base64,
		},
	}, nil
}
