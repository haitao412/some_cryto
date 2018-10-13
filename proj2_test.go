package proj2

import "github.com/nweaver/cs161-p2/userlib"
import "testing"
import "reflect"
import "github.com/google/uuid"
import "math/rand"
// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.
const letters = "qwertyuiopasdfghjklzxcvbnm"
const size = 5;
func NameGenerater() (userMaptr *map[string]string, err error) {
    var userMap map[string]string
    userMap = make(map[string]string)
    iter := 1
    for iter <= size {
        temp := make([]byte, rand.Intn(size) + 2)
        for i := range temp {
            temp[i] = letters[rand.Intn(len(letters))]
        }
        name := string(temp)
        password := uuid.New().String()
        userMap[name] = password
        iter = iter + 1
    }
    return &userMap, err
}
func TestInit(t *testing.T) {
	t.Log("Initialization test")
	userlib.DebugPrint = false
	someUsefulThings()
	userlib.DebugPrint = true
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// You probably want many more tests here.
    var userMaptr *map[string]string
    userMaptr,_ = NameGenerater()
    userMap := *userMaptr
    t.Log("Self Init users with total number of", size)
    for key, value := range userMap {
        u, err = InitUser(key, value)
        if err != nil {
            //t.Error says the test fails
            t.Error("Failed to self initialize user", err)
        }
        //t.Log() only produces output if you run with "go test -v"
        t.Log("Init user", u)
        t.Log("Init userpassword", value)
    }
    t.Log("Self get users with total number of", size)
    for key, value := range userMap {
        u, err = GetUser(key, value)
        if err != nil {
            //t.Error says the test fails
            t.Error("Failed to get user", err)
        }
        //t.Log() only produces output if you run with "go test -v"
        t.Log("Get user", u)
    }
    t.Log("Self test get users with Wrong password")
    for key, _ := range userMap {
        u, err = GetUser(key, "0000")
        if err != nil {
            //t.Error says the test fails
            t.Log("Correct get Wrong password:", err)
        }
        //t.Log() only produces output if you run with "go test -v"
        //t.Log("Got self user", u)
        //t.Log("Got self userpassword", value)
    }
    t.Log("Self test get users with Wrong Username")
    for _, value := range userMap {
        u, err = GetUser("aaaa", value)
        if err != nil {
            //t.Error says the test fails
            t.Log("Correct get Wrong Username:", err)
        }
        //t.Log() only produces output if you run with "go test -v"
        //t.Log("Got self user", u)
        //t.Log("Got self userpassword", value)
    }
}

func TestStorage(t *testing.T) {
	// And some more tests, because
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", u)

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
	}
}

func TestShare(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
	}

	var v, v2 []byte
	var msgid string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
	}

	msgid, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
	}
	err = u2.ReceiveFile("file2", "alice", msgid)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
	}

}
