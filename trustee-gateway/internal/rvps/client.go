package rvps

import (
	"context"

	"github.com/openanolis/trustee/gateway/internal/config"
	protos "github.com/openanolis/trustee/gateway/internal/rvps/protos"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// grpcClient is the implementation of ReferenceValueProviderServiceClient using gRPC
type GrpcClient struct {
	conn   *grpc.ClientConn
	client protos.ReferenceValueProviderServiceClient
}

// NewClient creates a new RVPS client based on the configuration
func NewClient(cfg *config.RVPSConfig) (*GrpcClient, error) {
	conn, err := grpc.NewClient(
		cfg.GRPCAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, err
	}

	client := protos.NewReferenceValueProviderServiceClient(conn)
	return &GrpcClient{
		conn:   conn,
		client: client,
	}, nil
}

// QueryReferenceValue queries reference values from RVPS
func (c *GrpcClient) QueryReferenceValue(ctx context.Context) (string, error) {
	resp, err := c.client.QueryReferenceValue(ctx, &protos.ReferenceValueQueryRequest{})
	if err != nil {
		logrus.Errorf("Failed to query reference values: %v", err)
		return "", err
	}
	return resp.ReferenceValueResults, nil
}

// RegisterReferenceValue registers a reference value with RVPS
func (c *GrpcClient) RegisterReferenceValue(ctx context.Context, message string) error {
	_, err := c.client.RegisterReferenceValue(ctx, &protos.ReferenceValueRegisterRequest{
		Message: message,
	})
	if err != nil {
		logrus.Errorf("Failed to register reference value: %v", err)
		return err
	}
	return nil
}

// Close closes the gRPC connection
func (c *GrpcClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}
