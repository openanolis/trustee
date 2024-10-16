package watcher

import "testing"

func Test_getKeyPath(t *testing.T) {
	type args struct {
		dir  string
		name string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "default.cosign-public-key.key => default/cosign-public-key/key",
			args: args{
				dir:  "foo",
				name: "default.cosign-public-key.key",
			},
			want: "foo/default/cosign-public-key/key",
		},
		{
			name: "default.cosign-public-key.cosign.key => default/cosign-public-key/cosign.key",
			args: args{
				dir:  "foo",
				name: "default.cosign-public-key.cosign.key",
			},
			want: "foo/default/cosign-public-key/cosign.key",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getKeyPath(tt.args.dir, tt.args.name); got != tt.want {
				t.Errorf("getKeyPath() = %v, want %v", got, tt.want)
			}
		})
	}
}
