use bulletproofs_amcl::transcript::TranscriptProtocol;
use std::ops::Mul;
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::{GroupElement};
use merlin::Transcript;

use bulletproofs_amcl::poseidon::{PoseidonSponge, DuplexSpongeMode, PoseidonConfig, find_poseidon_ark_and_mds};
use bulletproofs_amcl::poseidon::{poseidon_permute_prover, poseidon_permute_verifier};
use bulletproofs_amcl::r1cs::{ConstraintSystem, LinearCombination, Prover, Variable, Verifier};
use bulletproofs_amcl::r1cs::proof::R1CSProof;
use bulletproofs_amcl::utils::get_generators;

use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use amcl_wrapper::group_elem::GroupElementVector; // 确保导入 trait

use serde::Serialize; // ✅ 确保引入


/* ---------------- 结构体：把先前 HybridProof + Poseidon-R1CS 拼到一起 ---------------- */
macro_rules! static_labels_100 {
    () => {
        [
            b"T3a", b"T3b", b"T3c", b"T3d", b"T3e", b"T3f", b"T3g", b"T3h", b"T3i", b"T3j",
            b"T3k", b"T3l", b"T3m", b"T3n", b"T3o", b"T3p", b"T3q", b"T3r", b"T3s", b"T3t",
            b"T3u", b"T3v", b"T3w", b"T3x", b"T3y", b"T3z", b"T3A", b"T3B", b"T3C", b"T3D",
            b"T3E", b"T3F", b"T3G", b"T3H", b"T3I", b"T3J", b"T3K", b"T3L", b"T3M", b"T3N",
            b"T3O", b"T3P", b"T3Q", b"T3R", b"T3S", b"T3T", b"T3U", b"T3V", b"T3W", b"T3X",
            b"T3Y", b"T3Z", b"T30", b"T31", b"T32", b"T33", b"T34", b"T35", b"T36", b"T37",
            b"T38", b"T39", b"T40", b"T41", b"T42", b"T43", b"T44", b"T45", b"T46", b"T47",
            b"T48", b"T49", b"T50", b"T51", b"T52", b"T53", b"T54", b"T55", b"T56", b"T57",
            b"T58", b"T59", b"T60", b"T61", b"T62", b"T63", b"T64", b"T65", b"T66", b"T67",
            b"T68", b"T69", b"T70", b"T71", b"T72", b"T73", b"T74", b"T75", b"T76", b"T77"
        ]
    };
}
macro_rules! static_labels_10 {
    () => {
        [
            b"T3a", b"T3b", b"T3c", b"T3d", b"T3e", b"T3f", b"T3g", b"T3h", b"T3i", b"T3j"
            
        ]
    };
}
macro_rules! static_labels_500 {
    () => {
        [
            b"T3a", b"T3b", b"T3c", b"T3d", b"T3e", b"T3f", b"T3g", b"T3h", b"T3i", b"T3j",
            b"T3k", b"T3l", b"T3m", b"T3n", b"T3o", b"T3p", b"T3q", b"T3r", b"T3s", b"T3t",
            b"T3u", b"T3v", b"T3w", b"T3x", b"T3y", b"T3z", b"T3A", b"T3B", b"T3C", b"T3D",
            b"T3E", b"T3F", b"T3G", b"T3H", b"T3I", b"T3J", b"T3K", b"T3L", b"T3M", b"T3N",
            b"T3O", b"T3P", b"T3Q", b"T3R", b"T3S", b"T3T", b"T3U", b"T3V", b"T3W", b"T3X",
            b"T3Y", b"T3Z", b"T30", b"T31", b"T32", b"T33", b"T34", b"T35", b"T36", b"T37",
            b"T38", b"T39", b"T40", b"T41", b"T42", b"T43", b"T44", b"T45", b"T46", b"T47",
            b"T48", b"T49", b"T50", b"T51", b"T52", b"T53", b"T54", b"T55", b"T56", b"T57",
            b"T58", b"T59", b"T60", b"T61", b"T62", b"T63", b"T64", b"T65", b"T66", b"T67",
            b"T68", b"T69", b"T70", b"T71", b"T72", b"T73", b"T74", b"T75", b"T76", b"T77",
            b"T78", b"T79", b"T80", b"T81", b"T82", b"T83", b"T84", b"T85", b"T86", b"T87",
            b"T88", b"T89", b"T90", b"T91", b"T92", b"T93", b"T94", b"T95", b"T96", b"T97",
            b"T98", b"T99", b"T100", b"T101", b"T102", b"T103", b"T104", b"T105", b"T106", b"T107",
            b"T108", b"T109", b"T110", b"T111", b"T112", b"T113", b"T114", b"T115", b"T116", b"T117",
            b"T118", b"T119", b"T120", b"T121", b"T122", b"T123", b"T124", b"T125", b"T126", b"T127",
            b"T128", b"T129", b"T130", b"T131", b"T132", b"T133", b"T134", b"T135", b"T136", b"T137",
            b"T138", b"T139", b"T140", b"T141", b"T142", b"T143", b"T144", b"T145", b"T146", b"T147",
            b"T148", b"T149", b"T150", b"T151", b"T152", b"T153", b"T154", b"T155", b"T156", b"T157",
            b"T158", b"T159", b"T160", b"T161", b"T162", b"T163", b"T164", b"T165", b"T166", b"T167",
            b"T168", b"T169", b"T170", b"T171", b"T172", b"T173", b"T174", b"T175", b"T176", b"T177",
            b"T178", b"T179", b"T180", b"T181", b"T182", b"T183", b"T184", b"T185", b"T186", b"T187",
            b"T188", b"T189", b"T190", b"T191", b"T192", b"T193", b"T194", b"T195", b"T196", b"T197",
            b"T198", b"T199", b"T200", b"T201", b"T202", b"T203", b"T204", b"T205", b"T206", b"T207",
            b"T208", b"T209", b"T210", b"T211", b"T212", b"T213", b"T214", b"T215", b"T216", b"T217",
            b"T218", b"T219", b"T220", b"T221", b"T222", b"T223", b"T224", b"T225", b"T226", b"T227",
            b"T228", b"T229", b"T230", b"T231", b"T232", b"T233", b"T234", b"T235", b"T236", b"T237",
            b"T238", b"T239", b"T240", b"T241", b"T242", b"T243", b"T244", b"T245", b"T246", b"T247",
            b"T248", b"T249", b"T250", b"T251", b"T252", b"T253", b"T254", b"T255", b"T256", b"T257",
            b"T258", b"T259", b"T260", b"T261", b"T262", b"T263", b"T264", b"T265", b"T266", b"T267",
            b"T268", b"T269", b"T270", b"T271", b"T272", b"T273", b"T274", b"T275", b"T276", b"T277",
            b"T278", b"T279", b"T280", b"T281", b"T282", b"T283", b"T284", b"T285", b"T286", b"T287",
            b"T288", b"T289", b"T290", b"T291", b"T292", b"T293", b"T294", b"T295", b"T296", b"T297",
            b"T298", b"T299", b"T300", b"T301", b"T302", b"T303", b"T304", b"T305", b"T306", b"T307",
            b"T308", b"T309", b"T310", b"T311", b"T312", b"T313", b"T314", b"T315", b"T316", b"T317",
            b"T318", b"T319", b"T320", b"T321", b"T322", b"T323", b"T324", b"T325", b"T326", b"T327",
            b"T328", b"T329", b"T330", b"T331", b"T332", b"T333", b"T334", b"T335", b"T336", b"T337",
            b"T338", b"T339", b"T340", b"T341", b"T342", b"T343", b"T344", b"T345", b"T346", b"T347",
            b"T348", b"T349", b"T350", b"T351", b"T352", b"T353", b"T354", b"T355", b"T356", b"T357",
            b"T358", b"T359", b"T360", b"T361", b"T362", b"T363", b"T364", b"T365", b"T366", b"T367",
            b"T368", b"T369", b"T370", b"T371", b"T372", b"T373", b"T374", b"T375", b"T376", b"T377",
            b"T378", b"T379", b"T380", b"T381", b"T382", b"T383", b"T384", b"T385", b"T386", b"T387",
            b"T388", b"T389", b"T390", b"T391", b"T392", b"T393", b"T394", b"T395", b"T396", b"T397",
            b"T398", b"T399", b"T400", b"T401", b"T402", b"T403", b"T404", b"T405", b"T406", b"T407",
            b"T408", b"T409", b"T410", b"T411", b"T412", b"T413", b"T414", b"T415", b"T416", b"T417",
            b"T418", b"T419", b"T420", b"T421", b"T422", b"T423", b"T424", b"T425", b"T426", b"T427",
            b"T428", b"T429", b"T430", b"T431", b"T432", b"T433", b"T434", b"T435", b"T436", b"T437",
            b"T438", b"T439", b"T440", b"T441", b"T442", b"T443", b"T444", b"T445", b"T446", b"T447",
            b"T448", b"T449", b"T450", b"T451", b"T452", b"T453", b"T454", b"T455", b"T456", b"T457",
            b"T458", b"T459", b"T460", b"T461", b"T462", b"T463", b"T464", b"T465", b"T466", b"T467",
            b"T468", b"T469", b"T470", b"T471", b"T472", b"T473", b"T474", b"T475", b"T476", b"T477"
            
        ]
    };
}

macro_rules! static_labels_1000 {
    () => {
        [
            b"T0", b"T1", b"T2", b"T3", b"T4", b"T5", b"T6", b"T7", b"T8", b"T9",
            b"T10", b"T11", b"T12", b"T13", b"T14", b"T15", b"T16", b"T17", b"T18", b"T19",
            b"T20", b"T21", b"T22", b"T23", b"T24", b"T25", b"T26", b"T27", b"T28", b"T29",
            b"T30", b"T31", b"T32", b"T33", b"T34", b"T35", b"T36", b"T37", b"T38", b"T39",
            b"T40", b"T41", b"T42", b"T43", b"T44", b"T45", b"T46", b"T47", b"T48", b"T49",
            b"T50", b"T51", b"T52", b"T53", b"T54", b"T55", b"T56", b"T57", b"T58", b"T59",
            b"T60", b"T61", b"T62", b"T63", b"T64", b"T65", b"T66", b"T67", b"T68", b"T69",
            b"T70", b"T71", b"T72", b"T73", b"T74", b"T75", b"T76", b"T77", b"T78", b"T79",
            b"T80", b"T81", b"T82", b"T83", b"T84", b"T85", b"T86", b"T87", b"T88", b"T89",
            b"T90", b"T91", b"T92", b"T93", b"T94", b"T95", b"T96", b"T97", b"T98", b"T99",
            b"T100", b"T101", b"T102", b"T103", b"T104", b"T105", b"T106", b"T107", b"T108", b"T109",
            b"T110", b"T111", b"T112", b"T113", b"T114", b"T115", b"T116", b"T117", b"T118", b"T119",
            b"T120", b"T121", b"T122", b"T123", b"T124", b"T125", b"T126", b"T127", b"T128", b"T129",
            b"T130", b"T131", b"T132", b"T133", b"T134", b"T135", b"T136", b"T137", b"T138", b"T139",
            b"T140", b"T141", b"T142", b"T143", b"T144", b"T145", b"T146", b"T147", b"T148", b"T149",
            b"T150", b"T151", b"T152", b"T153", b"T154", b"T155", b"T156", b"T157", b"T158", b"T159",
            b"T160", b"T161", b"T162", b"T163", b"T164", b"T165", b"T166", b"T167", b"T168", b"T169",
            b"T170", b"T171", b"T172", b"T173", b"T174", b"T175", b"T176", b"T177", b"T178", b"T179",
            b"T180", b"T181", b"T182", b"T183", b"T184", b"T185", b"T186", b"T187", b"T188", b"T189",
            b"T190", b"T191", b"T192", b"T193", b"T194", b"T195", b"T196", b"T197", b"T198", b"T199",
            b"T200", b"T201", b"T202", b"T203", b"T204", b"T205", b"T206", b"T207", b"T208", b"T209",
            b"T210", b"T211", b"T212", b"T213", b"T214", b"T215", b"T216", b"T217", b"T218", b"T219",
            b"T220", b"T221", b"T222", b"T223", b"T224", b"T225", b"T226", b"T227", b"T228", b"T229",
            b"T230", b"T231", b"T232", b"T233", b"T234", b"T235", b"T236", b"T237", b"T238", b"T239",
            b"T240", b"T241", b"T242", b"T243", b"T244", b"T245", b"T246", b"T247", b"T248", b"T249",
            b"T250", b"T251", b"T252", b"T253", b"T254", b"T255", b"T256", b"T257", b"T258", b"T259",
            b"T260", b"T261", b"T262", b"T263", b"T264", b"T265", b"T266", b"T267", b"T268", b"T269",
            b"T270", b"T271", b"T272", b"T273", b"T274", b"T275", b"T276", b"T277", b"T278", b"T279",
            b"T280", b"T281", b"T282", b"T283", b"T284", b"T285", b"T286", b"T287", b"T288", b"T289",
            b"T290", b"T291", b"T292", b"T293", b"T294", b"T295", b"T296", b"T297", b"T298", b"T299",
            b"T300", b"T301", b"T302", b"T303", b"T304", b"T305", b"T306", b"T307", b"T308", b"T309",
            b"T310", b"T311", b"T312", b"T313", b"T314", b"T315", b"T316", b"T317", b"T318", b"T319",
            b"T320", b"T321", b"T322", b"T323", b"T324", b"T325", b"T326", b"T327", b"T328", b"T329",
            b"T330", b"T331", b"T332", b"T333", b"T334", b"T335", b"T336", b"T337", b"T338", b"T339",
            b"T340", b"T341", b"T342", b"T343", b"T344", b"T345", b"T346", b"T347", b"T348", b"T349",
            b"T350", b"T351", b"T352", b"T353", b"T354", b"T355", b"T356", b"T357", b"T358", b"T359",
            b"T360", b"T361", b"T362", b"T363", b"T364", b"T365", b"T366", b"T367", b"T368", b"T369",
            b"T370", b"T371", b"T372", b"T373", b"T374", b"T375", b"T376", b"T377", b"T378", b"T379",
            b"T380", b"T381", b"T382", b"T383", b"T384", b"T385", b"T386", b"T387", b"T388", b"T389",
            b"T390", b"T391", b"T392", b"T393", b"T394", b"T395", b"T396", b"T397", b"T398", b"T399",
            b"T400", b"T401", b"T402", b"T403", b"T404", b"T405", b"T406", b"T407", b"T408", b"T409",
            b"T410", b"T411", b"T412", b"T413", b"T414", b"T415", b"T416", b"T417", b"T418", b"T419",
            b"T420", b"T421", b"T422", b"T423", b"T424", b"T425", b"T426", b"T427", b"T428", b"T429",
            b"T430", b"T431", b"T432", b"T433", b"T434", b"T435", b"T436", b"T437", b"T438", b"T439",
            b"T440", b"T441", b"T442", b"T443", b"T444", b"T445", b"T446", b"T447", b"T448", b"T449",
            b"T450", b"T451", b"T452", b"T453", b"T454", b"T455", b"T456", b"T457", b"T458", b"T459",
            b"T460", b"T461", b"T462", b"T463", b"T464", b"T465", b"T466", b"T467", b"T468", b"T469",
            b"T470", b"T471", b"T472", b"T473", b"T474", b"T475", b"T476", b"T477", b"T478", b"T479",
            b"T480", b"T481", b"T482", b"T483", b"T484", b"T485", b"T486", b"T487", b"T488", b"T489",
            b"T490", b"T491", b"T492", b"T493", b"T494", b"T495", b"T496", b"T497", b"T498", b"T499",
            b"T500", b"T501", b"T502", b"T503", b"T504", b"T505", b"T506", b"T507", b"T508", b"T509",
            b"T510", b"T511", b"T512", b"T513", b"T514", b"T515", b"T516", b"T517", b"T518", b"T519",
            b"T520", b"T521", b"T522", b"T523", b"T524", b"T525", b"T526", b"T527", b"T528", b"T529",
            b"T530", b"T531", b"T532", b"T533", b"T534", b"T535", b"T536", b"T537", b"T538", b"T539",
            b"T540", b"T541", b"T542", b"T543", b"T544", b"T545", b"T546", b"T547", b"T548", b"T549",
            b"T550", b"T551", b"T552", b"T553", b"T554", b"T555", b"T556", b"T557", b"T558", b"T559",
            b"T560", b"T561", b"T562", b"T563", b"T564", b"T565", b"T566", b"T567", b"T568", b"T569",
            b"T570", b"T571", b"T572", b"T573", b"T574", b"T575", b"T576", b"T577", b"T578", b"T579",
            b"T580", b"T581", b"T582", b"T583", b"T584", b"T585", b"T586", b"T587", b"T588", b"T589",
            b"T590", b"T591", b"T592", b"T593", b"T594", b"T595", b"T596", b"T597", b"T598", b"T599",
            b"T600", b"T601", b"T602", b"T603", b"T604", b"T605", b"T606", b"T607", b"T608", b"T609",
            b"T610", b"T611", b"T612", b"T613", b"T614", b"T615", b"T616", b"T617", b"T618", b"T619",
            b"T620", b"T621", b"T622", b"T623", b"T624", b"T625", b"T626", b"T627", b"T628", b"T629",
            b"T630", b"T631", b"T632", b"T633", b"T634", b"T635", b"T636", b"T637", b"T638", b"T639",
            b"T640", b"T641", b"T642", b"T643", b"T644", b"T645", b"T646", b"T647", b"T648", b"T649",
            b"T650", b"T651", b"T652", b"T653", b"T654", b"T655", b"T656", b"T657", b"T658", b"T659",
            b"T660", b"T661", b"T662", b"T663", b"T664", b"T665", b"T666", b"T667", b"T668", b"T669",
            b"T670", b"T671", b"T672", b"T673", b"T674", b"T675", b"T676", b"T677", b"T678", b"T679",
            b"T680", b"T681", b"T682", b"T683", b"T684", b"T685", b"T686", b"T687", b"T688", b"T689",
            b"T690", b"T691", b"T692", b"T693", b"T694", b"T695", b"T696", b"T697", b"T698", b"T699",
            b"T700", b"T701", b"T702", b"T703", b"T704", b"T705", b"T706", b"T707", b"T708", b"T709",
            b"T710", b"T711", b"T712", b"T713", b"T714", b"T715", b"T716", b"T717", b"T718", b"T719",
            b"T720", b"T721", b"T722", b"T723", b"T724", b"T725", b"T726", b"T727", b"T728", b"T729",
            b"T730", b"T731", b"T732", b"T733", b"T734", b"T735", b"T736", b"T737", b"T738", b"T739",
            b"T740", b"T741", b"T742", b"T743", b"T744", b"T745", b"T746", b"T747", b"T748", b"T749",
            b"T750", b"T751", b"T752", b"T753", b"T754", b"T755", b"T756", b"T757", b"T758", b"T759",
            b"T760", b"T761", b"T762", b"T763", b"T764", b"T765", b"T766", b"T767", b"T768", b"T769",
            b"T770", b"T771", b"T772", b"T773", b"T774", b"T775", b"T776", b"T777", b"T778", b"T779",
            b"T780", b"T781", b"T782", b"T783", b"T784", b"T785", b"T786", b"T787", b"T788", b"T789",
            b"T790", b"T791", b"T792", b"T793", b"T794", b"T795", b"T796", b"T797", b"T798", b"T799",
            b"T800", b"T801", b"T802", b"T803", b"T804", b"T805", b"T806", b"T807", b"T808", b"T809",
            b"T810", b"T811", b"T812", b"T813", b"T814", b"T815", b"T816", b"T817", b"T818", b"T819",
            b"T820", b"T821", b"T822", b"T823", b"T824", b"T825", b"T826", b"T827", b"T828", b"T829",
            b"T830", b"T831", b"T832", b"T833", b"T834", b"T835", b"T836", b"T837", b"T838", b"T839",
            b"T840", b"T841", b"T842", b"T843", b"T844", b"T845", b"T846", b"T847", b"T848", b"T849",
            b"T850", b"T851", b"T852", b"T853", b"T854", b"T855", b"T856", b"T857", b"T858", b"T859",
            b"T860", b"T861", b"T862", b"T863", b"T864", b"T865", b"T866", b"T867", b"T868", b"T869",
            b"T870", b"T871", b"T872", b"T873", b"T874", b"T875", b"T876", b"T877", b"T878", b"T879",
            b"T880", b"T881", b"T882", b"T883", b"T884", b"T885", b"T886", b"T887", b"T888", b"T889",
            b"T890", b"T891", b"T892", b"T893", b"T894", b"T895", b"T896", b"T897", b"T898", b"T899",
            b"T900", b"T901", b"T902", b"T903", b"T904", b"T905", b"T906", b"T907", b"T908", b"T909",
            b"T910", b"T911", b"T912", b"T913", b"T914", b"T915", b"T916", b"T917", b"T918", b"T919",
            b"T920", b"T921", b"T922", b"T923", b"T924", b"T925", b"T926", b"T927", b"T928", b"T929",
            b"T930", b"T931", b"T932", b"T933", b"T934", b"T935", b"T936", b"T937", b"T938", b"T939",
            b"T940", b"T941", b"T942", b"T943", b"T944", b"T945", b"T946", b"T947", b"T948", b"T949",
            b"T950", b"T951", b"T952", b"T953", b"T954", b"T955", b"T956", b"T957", b"T958", b"T959",
            b"T960", b"T961", b"T962", b"T963", b"T964", b"T965", b"T966", b"T967", b"T968", b"T969",
            b"T970", b"T971", b"T972", b"T973", b"T974", b"T975", b"T976", b"T977", b"T978", b"T979",
            b"T980", b"T981", b"T982", b"T983", b"T984", b"T985", b"T986", b"T987", b"T988", b"T989",
            b"T990", b"T991", b"T992", b"T993", b"T994", b"T995", b"T996", b"T997", b"T998", b"T999",
        ]
    };
}

/// -------- batch size --------
const B: usize = 10;                    // number of (m,m′,W) tuples we handle
// 这里必须是static labels，不能动态生成
// const T3_LABELS: [&[u8]; 4] = [b"T3a", b"T3b", b"T3c", b"T3d"];   // static labels for Merlin
const T3_LABELS: [&'static [u8]; 10] = static_labels_10!();

#[derive(Clone, Debug)]
pub struct FullProof {
    /* --- Hybrid part (r & r′ unchanged) --- */
    pub T1: G1,
    pub T2: G1,
    pub T3: Vec<G1>,                       // ⬅️  now B commitments
    pub s_r: FieldElement,
    pub s_r_prime: FieldElement,
    pub s_m: Vec<FieldElement>,            // ⬅️  B responses
    pub s_m_prime: Vec<FieldElement>,      // ⬅️  B responses
    /* --- Poseidon‑R1CS part --- */
    pub r1cs_proof: R1CSProof,
    pub com_pk_rprime: G1,
    pub com_K:   G1,
    pub com_c:   Vec<G1>,                  // ⬅️  B commitments for c = m−K
    pub com_c_prime: Vec<G1>,              // ⬅️  B commitments for c′ = m′−K
    pub com_m:   Vec<G1>,                  // ⬅️  B commitments for m
    pub com_m_prime: Vec<G1>,             // ⬅️  B commitments for m′    
}

/* -------------------- Prover -------------------- */
#[allow(clippy::too_many_arguments)]
pub fn prove_full(
    g:&G1, h:&G1, pk:&G1,
    C1:&G1, C2:&G1, W:&[G1],          // ⬅️  B group elements
    r:&FieldElement, r_prime:&FieldElement,
    m:&[FieldElement], m_prime:&[FieldElement],
    poseidon_cfg:&PoseidonConfig,      // rate=2,cap=1
    ark_fe:&[Vec<FieldElement>], mds_fe:&[Vec<FieldElement>],
    G_vec:&[G1], H_vec:&[G1],
) -> FullProof {

    /* ------------------------------------------------------------------ */
    /*  0) 预计算具体的输入点  pk^{r'}  与   K = Poseidon(pk^{r'})         */
    /* ------------------------------------------------------------------ */

    // let t3_labels: Vec<Vec<u8>> = (0..B)
    //     .map(|i| format!("T3{}", (b'a' + i as u8) as char).into_bytes())
    //     .collect();

    // 0-1. 计算 pk^{r'} （群点）并压成字段元素
    let pk_rprime_pt = pk.mul(r_prime);
    let pk_rprime_bytes = pk_rprime_pt.to_bytes(true);                 // 48 B
    let pk_rprime_fe = FieldElement::from_bytes(&pk_rprime_bytes[1..]).unwrap();

    // 0-2. 原生 Poseidon 计算 K，用作电路输出的 *真实值*
    let K_native = {
        // use crate::poseidon::{PoseidonSponge, DuplexSpongeMode};
        let mut sponge = PoseidonSponge {
            parameters: poseidon_cfg.clone(),
            state: vec![FieldElement::zero(); 3],
            mode: DuplexSpongeMode::Absorbing { next_absorb_index: 0 },
        };
        sponge.absorb(0, &[pk_rprime_fe.clone()]);
        sponge.permute();
        let mut out = vec![FieldElement::zero(); 1];
        sponge.squeeze(0, &mut out);
        out[0].clone()
    };

    /* ------------------------------------------------------------------ */
    /*  1) Hybrid-Schnorr 片段（与之前相同）                              */
    /* ------------------------------------------------------------------ */
    let k_r       = FieldElement::random();
    let k_rprime  = FieldElement::random();

    let T1 = g .mul(&k_r);
    let T2 = pk.mul(&k_r) + &g.mul(&k_rprime);

    let mut T3              = Vec::with_capacity(B);
    let mut s_m             = Vec::with_capacity(B);
    let mut s_m_prime       = Vec::with_capacity(B);
    let mut com_m           = Vec::with_capacity(B);
    let mut var_m_vec       = Vec::with_capacity(B);
    let mut com_c           = Vec::with_capacity(B);
    let mut var_c_vec       = Vec::with_capacity(B);
    let mut com_c_prime     = Vec::with_capacity(B);
    let mut var_cprime_vec  = Vec::with_capacity(B);
    let mut com_m_prime     = Vec::with_capacity(B);
    let mut var_mprime_vec  = Vec::with_capacity(B);

    let mut tr = Transcript::new(b"HybridPoseidon");

    /* ① 先写入公开量 */
    tr.commit_point(b"g",  g);
    tr.commit_point(b"h",  h);
    tr.commit_point(b"pk", pk);
    tr.commit_point(b"C1", C1);
    tr.commit_point(b"C2", C2);
    tr.commit_point(b"W",  &W[0]);  // Commit at least one W for transcript consistency (optional)

    /* ② 生成并提交 B 个 Schnorr 承诺（T3_i） */
    for i in 0..B {
        // fresh randomness per tuple
        let k_m_i       = FieldElement::random();
        let k_mprime_i  = FieldElement::random();

        let T3_i = g.mul(&k_m_i) + &h.mul(&k_mprime_i);
        tr.commit_point(T3_LABELS[i], &T3_i);

        T3.push(T3_i);

        // will fill s_m *_i later after challenge
        s_m.push(k_m_i);        // temporarily store k_m_i
        s_m_prime.push(k_mprime_i);
    }

    /* ③ 再写入两个 Schnorr 承诺 */
    tr.commit_point(b"T1", &T1);
    tr.commit_point(b"T2", &T2);

    /* ④ 现在生成 challenge */
    let c = tr.challenge_scalar(b"c");

    /* ⑤ 提前生成四个 Schnorr 响应（必须在 Transcript交给Prover之前完成！） */
    let s_r        = &k_r       + &(c.clone() * r);
    let s_r_prime  = &k_rprime  + &(c.clone() * r_prime);
    for i in 0..B {
        let resp_m  = &s_m[i] + &(c.clone() * &m[i]);
        let resp_mp = &s_m_prime[i] + &(c.clone() * &m_prime[i]);
        s_m[i]       = resp_m;
        s_m_prime[i] = resp_mp;
    }

    let mut prov = Prover::new(g, h, &mut tr);

    /* 2-1. 提交外部变量 pk^{r'}、K 作为 “Committed 变量” */
    let (com_pk_rprime , var_pk_rprime) = prov.commit(pk_rprime_fe.clone(), FieldElement::random());
    let (com_K         , var_K        ) = prov.commit(K_native.clone()  , FieldElement::random());

    /* 2-2. 调 Poseidon gadget：state = [pk^{r'}, 0, 0] */
    let mut state_vars = vec![
        prov.allocate(Some(FieldElement::zero())).unwrap(),
        var_pk_rprime,
        prov.allocate(Some(FieldElement::zero())).unwrap(),
    ];

    // full_rounds 与 partial_rounds 直接从 cfg 里拿
    state_vars = poseidon_permute_prover(
        &mut prov,
        state_vars.clone(),           // 传入 state
        ark_fe,
        mds_fe,
        poseidon_cfg.full_rounds,
        poseidon_cfg.partial_rounds,
    );

    // 约束 state_vars[0] == K
    prov.constrain(state_vars[poseidon_cfg.capacity] - var_K);

    /* 2-3. 对每个 i 处理 m_i, c_i, c'_i 的 Pedersen 承诺以及约束 */
    for i in 0..B {
        // Pedersen commits: m_i
        let (cm,  var_m)  = prov.commit(m[i].clone(), FieldElement::random());
        com_m.push(cm);  var_m_vec.push(var_m);

        // c_i = m_i - K
        let c_i = &m[i] - &K_native;
        let (cc, var_c)  = prov.commit(c_i.clone(), FieldElement::random());
        com_c.push(cc);   var_c_vec.push(var_c);

        // c′_i = m′_i - K
        let cprime_i = &m_prime[i] - &K_native;
        let (ccp, var_cp) = prov.commit(cprime_i.clone(), FieldElement::random());
        com_c_prime.push(ccp);  var_cprime_vec.push(var_cp);

        // add constraints:   m_i - K - c_i == 0   and   m′_i - K - c′_i == 0
        prov.constrain(var_m  - var_K - var_c);
        let (cmprime, var_mprime) = prov.commit(m_prime[i].clone(), FieldElement::random());
        com_m_prime.push(cmprime);  var_mprime_vec.push(var_mprime);
        prov.constrain(var_mprime - var_K - var_cp);
    }

    /* 2-4. 任选生成几条 debug 输出（可删） */
    // println!("pk^r'   = {}", pk_rprime_fe.to_hex());
    // println!("PoseidonK = {}", K_native.to_hex());

    /* 2-5. 生成 R1CS 证明 */
    let (G_vec, H_vec): (Vec<G1>, Vec<G1>) = (G_vec.into(), H_vec.into());
    let r1cs_proof = prov.prove(&G_vec.into(), &H_vec.into()).unwrap();

    /* ------------------------------------------------------------------ */
    /*   3) 打包所有内容为 FullProof                                      */
    /* ------------------------------------------------------------------ */
    FullProof {
        T1, T2, T3,
        s_r,
        s_r_prime,
        s_m,
        s_m_prime,
        r1cs_proof,
        com_pk_rprime,
        com_K,
        com_c,
        com_c_prime,
        com_m,
        com_m_prime,
    }
}

/* ----------------------- Verifier（思路） -----------------------
   1. 复现 Hybrid Transcript → 计算同一个 c
   2. 检查三条 Schnorr 等式 (见上条回答)
   3. 用 r1cs::Verifier，把
        • com_pk_rprime 作为外部 committed 变量 0
        • poseidon_permute_r1cs 复算约束
        • 额外约束   var_m - var_K - var_c = 0   和 var_m - var_K - var_cprime + var_c - var_cprime = 0
      并验证 r1cs_proof
   -------------------------------------------------------------- */
/// 验证完整证明
#[allow(clippy::too_many_arguments)]
pub fn verify_full(
    g:&G1, h:&G1, pk:&G1,
    C1:&G1, C2:&G1, W:&[G1],      // ⬅️  B group elements
    proof:&FullProof,
    poseidon_cfg:&PoseidonConfig,
    ark_fe:&[Vec<FieldElement>], mds_fe:&[Vec<FieldElement>],
    G_vec:&[G1], H_vec:&[G1],
) -> bool {

    // let t3_labels: Vec<Vec<u8>> = (0..B)
    //     .map(|i| format!("T3{}", (b'a' + i as u8) as char).into_bytes())
    //     .collect();

    let mut tr = Transcript::new(b"HybridPoseidon");

    /* ① 公开量 */
    tr.commit_point(b"g",  g);
    tr.commit_point(b"h",  h);
    tr.commit_point(b"pk", pk);
    tr.commit_point(b"C1", C1);
    tr.commit_point(b"C2", C2);
    tr.commit_point(b"W",  &W[0]);  // Commit at least one W for transcript consistency (optional)

    /* ② Schnorr 承诺 T3_i */
    for i in 0..B {
        tr.commit_point(T3_LABELS[i], &proof.T3[i]);
    }

    /* ③ Schnorr 承诺 T1, T2 */
    tr.commit_point(b"T1", &proof.T1);
    tr.commit_point(b"T2", &proof.T2);

    /* ④ 同一位置取 challenge */
    let c = tr.challenge_scalar(b"c");

    /* ⑤ 再创建 R1CS Verifier —— 后续逻辑不变 */
    let mut verifier = Verifier::new(&mut tr);

    /* 2-1. 依 **与 Prover 相同的顺序** 提交外部承诺 */
    let var_pk_rprime = verifier.commit(proof.com_pk_rprime.clone());
    let var_K         = verifier.commit(proof.com_K.clone());

    let mut var_m_vec      = Vec::with_capacity(B);
    let mut var_c_vec      = Vec::with_capacity(B);
    let mut var_cprime_vec = Vec::with_capacity(B);
    let mut var_mprime_vec = Vec::with_capacity(B);
    
    for i in 0..B {
        var_m_vec.push( verifier.commit(proof.com_m[i].clone()) );
        var_c_vec.push( verifier.commit(proof.com_c[i].clone()) );
        var_cprime_vec.push( verifier.commit(proof.com_c_prime[i].clone()) );
        var_mprime_vec.push( verifier.commit(proof.com_m_prime[i].clone()) );
    }

    /* 2-2. 准备 Poseidon 状态变量并复现同样的约束 */
    let mut state_vars = vec![
        verifier.allocate(Some(FieldElement::zero())).unwrap(),
        var_pk_rprime,
        verifier.allocate(Some(FieldElement::zero())).unwrap(),
    ];

    state_vars = poseidon_permute_verifier(
        &mut verifier,
        state_vars.clone(),
        ark_fe,
        mds_fe,
        poseidon_cfg.full_rounds,
        poseidon_cfg.partial_rounds,
    );
    verifier.constrain(state_vars[poseidon_cfg.capacity] - var_K);          // K = state[0]

    /* 2-3. 约束   m − K − c = 0   和   m′ − K − c′ = 0 */
    for i in 0..B {
        verifier.constrain(var_m_vec[i] - var_K - var_c_vec[i]);
        verifier.constrain(var_mprime_vec[i] - var_K - var_cprime_vec[i]);
    }

    /* --------------------------------------------------------- */
    /* 3) 计算 Schnorr-style challenge c 并验证三条等式           */
    /*    ※ 必须在 verifier.build() 之前读取！                    */
    /* --------------------------------------------------------- */
    

    let ok1 = g .mul(&proof.s_r) ==
              &proof.T1 + &C1.mul(&c);
    let ok2 = pk.mul(&proof.s_r) + &g.mul(&proof.s_r_prime) ==
              &proof.T2 + &C2.mul(&c);
    let ok3 = (0..B).all(|i| {
        g.mul(&proof.s_m[i]) + &h.mul(&proof.s_m_prime[i]) ==
            &proof.T3[i] + &W[i].clone().mul(&c)
    });

    println!("[Verifier] ok1 (C1 = g^r): {}", ok1);
    println!("[Verifier] ok2 (C2 = pk^r + g^r'): {}", ok2);
    println!("[Verifier] ok3 (W  = g^m h^m'): {}", ok3);

    /* --------------------------------------------------------- */
    /* 4) 验证 R1CS 证明                                         */
    /* --------------------------------------------------------- */
    let r1cs_ok = verifier
        .verify(&proof.r1cs_proof, &g, &h, &G_vec.into(), &H_vec.into())
        .is_ok();
    
    println!("[Verifier] ok4 (Poseidon R1CS proof): {}", r1cs_ok);


    ok1 && ok2 && ok3 && r1cs_ok
}

/* ----------------------- 单元测试 ------------------------------- */
#[test]
fn full_hybrid_poseidon_ok() {
    /* —— 公共参数 —— */
    let g  = G1::from_msg_hash(b"g");
    let h  = G1::from_msg_hash(b"h");
    let sk = FieldElement::from(123u64);
    let pk = g.clone().mul(&sk);

    /* —— witness —— */
    let r  = FieldElement::from(77u64);
    let r_prime = FieldElement::from(314u64);

    let m_vals: Vec<FieldElement> = (0..B).map(|i| FieldElement::from(42u64 + i as u64)).collect();
    let mprime_vals: Vec<FieldElement> = (0..B).map(|i| FieldElement::from(2024u64 + i as u64)).collect();
    let W_vec: Vec<G1> = (0..B).map(|i| g.clone().mul(&m_vals[i]) + &h.clone().mul(&mprime_vals[i])).collect();
    println!("W_vec: {:#?}", W_vec);

    /* —— statement C1, C2 —— */
    let C1 = g.clone().mul(&r);
    let C2 = pk.clone().mul(&r) + &g.clone().mul(&r_prime);

    /* Poseidon 参数（rate=2, capacity=1） */
    let (ark, mds) = find_poseidon_ark_and_mds(
        255, 2, 8, 57, 0);         // 示例：full=8,partial=57,alpha=5
    println!("hybrid ark[0] len: {}", ark[0].len());
    println!("hybrid mds len: {}", mds.len());
    println!("hybrid mds[0] len: {}", mds[0].len());
    let cfg = PoseidonConfig::new(
        8, 57, 5, mds.clone(), ark.clone(), 2, 1);

    /* —— Bulletproof generators —— */
    let gens = 8usize.next_power_of_two();       // 测试随便取 ≥ 8
    let G_vec = get_generators("G", 4096);
    let H_vec = get_generators("H", 4096);

    /* —— 生成证明 —— */
    let proof = prove_full(
        &g,&h,&pk,&C1,&C2,&W_vec,
        &r,&r_prime,
        &m_vals,&mprime_vals,
        &cfg,&ark,&mds,&G_vec,&H_vec);

    println!("Proving done");

    let mut total_bytes = 0;

    // G1 类型成员（压缩为 48 bytes）
    total_bytes += proof.T1.to_bytes(true).len();
    total_bytes += proof.T2.to_bytes(true).len();
    total_bytes += proof.T3.iter().map(|pt| pt.to_bytes(true).len()).sum::<usize>();
    total_bytes += proof.com_pk_rprime.to_bytes(true).len();
    total_bytes += proof.com_K.to_bytes(true).len();
    total_bytes += proof.com_c.iter().map(|pt| pt.to_bytes(true).len()).sum::<usize>();
    total_bytes += proof.com_c_prime.iter().map(|pt| pt.to_bytes(true).len()).sum::<usize>();
    total_bytes += proof.com_m.iter().map(|pt| pt.to_bytes(true).len()).sum::<usize>();
    total_bytes += proof.com_m_prime.iter().map(|pt| pt.to_bytes(true).len()).sum::<usize>();

    // FieldElement 类型成员（AMCL字段默认 48 bytes）
    total_bytes += proof.s_r.to_bytes().len();
    total_bytes += proof.s_r_prime.to_bytes().len();
    total_bytes += proof.s_m.iter().map(|f| f.to_bytes().len()).sum::<usize>();
    total_bytes += proof.s_m_prime.iter().map(|f| f.to_bytes().len()).sum::<usize>();

    // R1CSProof：目前你没法直接看大小，但你可以看一下内含的向量长度
    use std::mem::size_of_val;
    println!("R1CSProof type = {:?}", std::any::type_name::<R1CSProof>());
    println!("R1CSProof size (stack only): {} bytes", size_of_val(&proof.r1cs_proof));

    // 输出总长度
    println!("Approx proof byte size (excluding R1CS): {} bytes", total_bytes);
    
    /* —— Verify —— */
    assert!(
        verify_full(
            &g,&h,&pk,&C1,&C2,&W_vec,
            &proof,
            &cfg,&ark,&mds,&G_vec,&H_vec
        ),
        "verification failed"
    );
}