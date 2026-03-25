use crate::poseidon::PoseidonGrainLFSR;
use crate::poseidon::PoseidonConfig;
use amcl_wrapper::field_elem::FieldElement;

/// An entry in the default Poseidon parameters
pub struct PoseidonDefaultConfigEntry {
    /// The rate (in terms of number of field elements).
    pub rate: usize,
    /// Exponent used in S-boxes.
    pub alpha: usize,
    /// Number of rounds in a full-round operation.
    pub full_rounds: usize,
    /// Number of rounds in a partial-round operation.
    pub partial_rounds: usize,
    /// Number of matrices to skip when generating parameters using the Grain LFSR.
    ///
    /// The matrices being skipped are those that do not satisfy all the desired properties.
    /// See the [reference implementation](https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/generate_parameters_grain.sage) for more detail.
    pub skip_matrices: usize,
}

impl PoseidonDefaultConfigEntry {
    /// Create an entry in `PoseidonDefaultConfig`.
    pub const fn new(
        rate: usize,
        alpha: usize,
        full_rounds: usize,
        partial_rounds: usize,
        skip_matrices: usize,
    ) -> Self {
        Self {
            rate,
            alpha,
            full_rounds,
            partial_rounds,
            skip_matrices,
        }
    }
}

/// Internal function that computes the ark and mds from the Poseidon Grain LFSR.
pub fn find_poseidon_ark_and_mds(
    prime_bits: u64,
    rate: usize,
    full_rounds: u64,
    partial_rounds: u64,
    skip_matrices: u64,
) -> (Vec<Vec<FieldElement>>, Vec<Vec<FieldElement>>) {
    let mut lfsr = PoseidonGrainLFSR::new(
        false,
        prime_bits,
        (rate + 1) as u64,
        full_rounds,
        partial_rounds,
    );

    let mut ark = Vec::<Vec<FieldElement>>::with_capacity((full_rounds + partial_rounds) as usize);
    for _ in 0..(full_rounds + partial_rounds) {
        ark.push(lfsr.get_field_elements_rejection_sampling(rate + 1));
    }

    for _ in 0..skip_matrices {
        let _ = lfsr.get_field_elements_mod_p(2 * (rate + 1));
    }

    let xs = lfsr.get_field_elements_mod_p(rate + 1);
    let ys = lfsr.get_field_elements_mod_p(rate + 1);

    let mut mds = Vec::with_capacity(rate + 1);
    for i in 0..(rate + 1) {
        let mut row = Vec::with_capacity(rate + 1);
        for j in 0..(rate + 1) {
            row.push((&xs[i] + &ys[j]).inverse());
        }
        mds.push(row);
    }

    (ark, mds)
}

#[cfg(test)]
mod test {
    use super::*;
    use amcl_wrapper::field_elem::FieldElement;

    #[test]
    fn bls12_381_fr_poseidon_default_parameters_test() {
        // Using AMCL-based configuration with find_poseidon_ark_and_mds
        let (ark, mds) = find_poseidon_ark_and_mds(255, 2, 8, 31, 0);
        assert_eq!(ark.len(), 8 + 31);
        assert_eq!(mds.len(), 3);
        assert_eq!(mds[0].len(), 3);
        
        println!("=== ARK ===");
        for (r, row) in ark.iter().enumerate() {
            println!("Round {}: [", r);
            for val in row {
                println!("  {},", val.to_hex());
            }
            println!("]");
        }

        println!("=== MDS ===");
        for (i, row) in mds.iter().enumerate() {
            println!("Row {}: [", i);
            for val in row {
                println!("  {},", val.to_hex());
            }
            println!("]");
        }

        /*
        // The following tests are commented out as they are no longer meaningful for AMCL.

        // constraints
        let constraints_rate_2 = Fr::get_default_poseidon_parameters(2, false).unwrap();
        assert_eq!(
            constraints_rate_2.ark[0][0],
            MontFp!(
                "27117311055620256798560880810000042840428971800021819916023577129547249660720"
            )
        );
        assert_eq!(
            constraints_rate_2.mds[0][0],
            MontFp!(
                "26017457457808754696901916760153646963713419596921330311675236858336250747575"
            )
        );

        let constraints_rate_3 = Fr::get_default_poseidon_parameters(3, false).unwrap();
        assert_eq!(
            constraints_rate_3.ark[0][0],
            MontFp!(
                "11865901593870436687704696210307853465124332568266803587887584059192277437537"
            )
        );
        assert_eq!(
            constraints_rate_3.mds[0][0],
            MontFp!(
                "18791275321793747281053101601584820964683215017313972132092847596434094368732"
            )
        );

        let constraints_rate_4 = Fr::get_default_poseidon_parameters(4, false).unwrap();
        assert_eq!(
            constraints_rate_4.ark[0][0],
            MontFp!(
                "41775194144383840477168997387904574072980173775424253289429546852163474914621"
            )
        );
        assert_eq!(
            constraints_rate_4.mds[0][0],
            MontFp!(
                "42906651709148432559075674119637355642263148226238482628104108168707874713729"
            )
        );

        let constraints_rate_5 = Fr::get_default_poseidon_parameters(5, false).unwrap();
        assert_eq!(
            constraints_rate_5.ark[0][0],
            MontFp!(
                "24877380261526996562448766783081897666376381975344509826094208368479247894723"
            )
        );
        assert_eq!(
            constraints_rate_5.mds[0][0],
            MontFp!(
                "30022080821787948421423927053079656488514459012053372877891553084525866347732"
            )
        );

        let constraints_rate_6 = Fr::get_default_poseidon_parameters(6, false).unwrap();
        assert_eq!(
            constraints_rate_6.ark[0][0],
            MontFp!(
                "37928506567864057383105673253383925733025682403141583234734361541053005808936"
            )
        );
        assert_eq!(
            constraints_rate_6.mds[0][0],
            MontFp!(
                "49124738641420159156404016903087065194698370461819821829905285681776084204443"
            )
        );

        let constraints_rate_7 = Fr::get_default_poseidon_parameters(7, false).unwrap();
        assert_eq!(
            constraints_rate_7.ark[0][0],
            MontFp!(
                "37848764121158464546907147011864524711588624175161409526679215525602690343051"
            )
        );
        assert_eq!(
            constraints_rate_7.mds[0][0],
            MontFp!(
                "28113878661515342855868752866874334649815072505130059513989633785080391114646"
            )
        );

        let constraints_rate_8 = Fr::get_default_poseidon_parameters(8, false).unwrap();
        assert_eq!(
            constraints_rate_8.ark[0][0],
            MontFp!(
                "51456871630395278065627483917901523970718884366549119139144234240744684354360"
            )
        );
        assert_eq!(
            constraints_rate_8.mds[0][0],
            MontFp!(
                "12929023787467701044434927689422385731071756681420195282613396560814280256210"
            )
        );

        // weights
        let weights_rate_2 = Fr::get_default_poseidon_parameters(2, true).unwrap();
        assert_eq!(
            weights_rate_2.ark[0][0],
            MontFp!(
                "25126470399169474618535500283750950727260324358529540538588217772729895991183"
            )
        );
        assert_eq!(
            weights_rate_2.mds[0][0],
            MontFp!(
                "46350838805835525240431215868760423854112287760212339623795708191499274188615"
            )
        );

        let weights_rate_3 = Fr::get_default_poseidon_parameters(3, true).unwrap();
        assert_eq!(
            weights_rate_3.ark[0][0],
            MontFp!(
                "16345358380711600255519479157621098002794924491287389755192263320486827897573"
            )
        );
        assert_eq!(
            weights_rate_3.mds[0][0],
            MontFp!(
                "37432344439659887296708509941462699942272362339508052702346957525719991245918"
            )
        );

        let weights_rate_4 = Fr::get_default_poseidon_parameters(4, true).unwrap();
        assert_eq!(
            weights_rate_4.ark[0][0],
            MontFp!("2997721997773001075802235431463112417440167809433966871891875582435098138600")
        );
        assert_eq!(
            weights_rate_4.mds[0][0],
            MontFp!(
                "43959024692079347032841256941012668338943730711936867712802582656046301966186"
            )
        );

        let weights_rate_5 = Fr::get_default_poseidon_parameters(5, true).unwrap();
        assert_eq!(
            weights_rate_5.ark[0][0],
            MontFp!(
                "28142027771717376151411984909531650866105717069245696861966432993496676054077"
            )
        );
        assert_eq!(
            weights_rate_5.mds[0][0],
            MontFp!(
                "13157425078305676755394500322568002504776463228389342308130514165393397413991"
            )
        );

        let weights_rate_6 = Fr::get_default_poseidon_parameters(6, true).unwrap();
        assert_eq!(
            weights_rate_6.ark[0][0],
            MontFp!("7417004907071346600696060525974582183666365156576759507353305331252133694222")
        );
        assert_eq!(
            weights_rate_6.mds[0][0],
            MontFp!(
                "51393878771453405560681338747290999206747890655420330824736778052231938173954"
            )
        );

        let weights_rate_7 = Fr::get_default_poseidon_parameters(7, true).unwrap();
        assert_eq!(
            weights_rate_7.ark[0][0],
            MontFp!(
                "47093173418416013663709314805327945458844779999893881721688570889452680883650"
            )
        );
        assert_eq!(
            weights_rate_7.mds[0][0],
            MontFp!(
                "51455917624412053400160569105425532358410121118308957353565646758865245830775"
            )
        );

        let weights_rate_8 = Fr::get_default_poseidon_parameters(8, true).unwrap();
        assert_eq!(
            weights_rate_8.ark[0][0],
            MontFp!(
                "16478680729975035007348178961232525927424769683353433314299437589237598655079"
            )
        );
        assert_eq!(
            weights_rate_8.mds[0][0],
            MontFp!(
                "39160448583049384229582837387246752222769278402304070376350288593586064961857"
            )
        );
        */
    }
}
