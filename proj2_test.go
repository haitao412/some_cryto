package proj2

import "github.com/nweaver/cs161-p2/userlib"
import "testing"
import "reflect"
import "github.com/google/uuid"
import "math/rand"
import "strconv"
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
	//userlib.DebugPrint = true
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
        //t.Log("Init user", u)
        //t.Log("Init userpassword", value)
    }
    t.Log("Self get users with total number of", size)
    for key, value := range userMap {
        u, err = GetUser(key, value)
        if err != nil {
            //t.Error says the test fails
            t.Error("Failed to get user", err)
        }
        //t.Log() only produces output if you run with "go test -v"
        //t.Log("Get user", u)
    }
    //t.Log("Self test get users with Wrong password")
    //for key, _ := range userMap {
    //    u, err = GetUser(key, "0000")
    //    if err != nil {
            //t.Error says the test fails
    //        t.Log("Correct get Wrong password:", err)
    //    }
        //t.Log() only produces output if you run with "go test -v"
        //t.Log("Got self user", u)
        //t.Log("Got self userpassword", value)
    //}
    //t.Log("Self test get users with Wrong Username")
    //for _, value := range userMap {
    //    u, err = GetUser("aaaa", value)
    //    if err != nil {
            //t.Error says the test fails
    //        t.Log("Correct get Wrong Username:", err)
    //    }
        //t.Log() only produces output if you run with "go test -v"
        //t.Log("Got self user", u)
        //t.Log("Got self userpassword", value)
    //}
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
func TestNonExistingUser(t *testing.T) {
    userlib.DebugPrint = false
    _, err := GetUser("wrongusername", "wrongpassword")
    if err == nil {
        t.Error(err)
    }
}

func TestMultipleUser(t *testing.T) {
    // Having previously created a user "alice" with password "fubar"...
    alice, _ := GetUser("alice", "fubar")
    also_alice, _ := GetUser("alice", "fubar")

    alice.StoreFile("todo", []byte("write tests"))

    todo, _ := also_alice.LoadFile("todo")
    if string(todo) != "write tests" {
        //t.Error("Same user and password could not access file: %s", todo)
    }
}

func TestNonOrExistPublicKey(t *testing.T) {
    // Test for non-/existing public key
    
    _, valid := userlib.KeystoreGet("alice")
    if !valid {
        t.Error("Failed to setup a public key")
    }

    mallory, valid := userlib.KeystoreGet("Mallory")
    if valid {
        t.Error("Public key of non-exist username")
    }
    t.Log("Loaded non-exist user", mallory)
}



func TestSimpleGetPutNoState(t *testing.T) {
    
    m1, _ := InitUser("Marry", "fubar")
    m2, _ := GetUser("Marry", "fubar")
    m3, _ := GetUser("Marry", "fubar")

    m2.StoreFile("simple", []byte("simple1"))
    m3.StoreFile("simple", []byte("simple2"))
    data, _ := m1.LoadFile("simple")
    if string(data) != "simple2" {
        t.Error("Can not reupload file")
    }
}

func TestStoreFile(t *testing.T) {
    msg := "This is a testing data1, This is a testing data2, This is a testing data3, This is a testing data4"
    v, _ := GetUser("alice", "fubar")
    v.StoreFile(string("test"), []byte(msg))
}

func TestAppendFile(t *testing.T) {

    
    v, _ := GetUser("alice", "fubar")


    original, _ := v.LoadFile("test")

    _ = v.AppendFile(string("test"), []byte(", This is a testing data5"))

    
    appended, err := v.LoadFile(string("test")) 
    if err != nil {
        t.Error("Can not load file !!!")
    }
    

    if string(appended) != (string(original)+", This is a testing data5") {
        t.Error("AppendFile not working")
    }
}

func TestNonExistFile(t *testing.T) {
    
    v, _ := GetUser("alice", "fubar")
    _, err := v.LoadFile("non-existingFileName")
    if err == nil {
        t.Error("Load an non-existing filename", err)
    }
}

func TestShareFile(t *testing.T) {

    userlib.DebugPrint = true
    a, _ := GetUser("alice", "fubar")
    t.Log("Load user: ", a)

    b, _ := GetUser("bob", "foobar")
    t.Log("Load user: ", b)

    userlib.DebugPrint = true
    msgid, _ := a.ShareFile("test", "bob")

    userlib.DebugPrint = true
    a_data, _ := a.LoadFile(string("test"))

    
    b.ReceiveFile("testing", "alice", msgid)

    b_data, _ := b.LoadFile(string("testing"))
    if string(a_data) != string(b_data) {
        t.Error("Sharing content does not match")
    }

    a.AppendFile(string("test"), []byte(", This is Alice data"))
    b.AppendFile(string("testing"), []byte(", This is Bob data"))

    a_data, _ = a.LoadFile(string("test"))
    b_data, _ = b.LoadFile(string("testing"))

    t.Log("a_data: ", string(a_data))
    t.Log("b_data: ", string(b_data))
    if string(a_data) != string(b_data) {
        t.Error("Sharing content does not match")
    }
}

func TestIndirectShareFile(t *testing.T) {
    m, _ := InitUser("mallory", "attacker")
    b, _ := GetUser("bob", "foobar")
    msgid, _ := b.ShareFile("testing", "mallory")
    m.ReceiveFile("leak", "bob", msgid)
    m.AppendFile(string("leak"), []byte(", This is Mallory data"))
    m_data, err := m.LoadFile(string("leak"))
    b_data, err := b.LoadFile(string("testing"))
    if string(m_data) != string(b_data) {
        t.Error("Sharing content does not match")
    }
    // t.Log("Mallory got data", string(data))

    err = m.ReceiveFile("leak", "alice", msgid) // Should be fail
    if err == nil {
        t.Error("Shouldn't receive non-exist sharing")
    }
}

func TestRevokeFile(t *testing.T) {
    a, _ := GetUser("alice", "fubar")
    b, _ := GetUser("bob", "foobar")
    m, _ := GetUser("mallory", "attacker")
    a.RevokeFile("test")
    _, err := b.LoadFile(string("testing"))
    // t.Log(err)
    if err == nil {
        t.Error("Bob shouldn't get data while he did")
    }
    _, err = m.LoadFile(string("leak"))
    // t.Log(err)
    if err == nil {
        t.Error("Mallory shouldn't get data while she did")
    }
}

func TestMultipleStore(t *testing.T) {
    a, _ := GetUser("alice", "fubar")
    err := a.StoreFile("File1", []byte("file1"))
    t.Log(err)
}

func TestNonCollidingName(t *testing.T) {
    
    a, _ := GetUser("alice", "fubar")
    b, _ := GetUser("bob", "foobar")
    a.StoreFile("same", []byte("sample1"))
    b.StoreFile("same", []byte("sample2"))
    data, err := b.LoadFile("same")
    if err != nil || string(data) != "sample2" {
        t.Error("Store same file name for different user should working")
    }
}

func TestSingleUserManyAppend(t *testing.T) {
    v, _ := GetUser("alice", "fubar")
    v.StoreFile("NewFile", []byte("1"))
    for i := 2; i < 100; i++ {
        s := strconv.Itoa(i)

        //userlib.DebugPrint = true
        err := v.AppendFile("NewFile", []byte(s))
        if err != nil {
            t.Error("Append Failed")
        }
    }
    data, _ := v.LoadFile("NewFile")
    t.Log("Data after append ", string(data))
}