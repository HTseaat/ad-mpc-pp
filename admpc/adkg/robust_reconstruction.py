from adkg.polynomial import polynomials_over
from adkg.reed_solomon import (
    Algorithm,
    EncoderFactory,
    DecoderFactory,
    RobustDecoderFactory,
)
from adkg.reed_solomon import IncrementalDecoder

# TODO: Abstract this to a separate file instead of importing it from here.
from adkg.batch_reconstruction import fetch_one


def find_inconsistent_dealers(poly, shares_list, key_proposal, point):
    """Check every available point against an already decoded polynomial.

    ``IncrementalDecoder`` may finish after ``n-t`` consistent points and then
    intentionally ignores later calls to ``add``. ADtrans already has all ACSS
    candidates available, so its formal Byzantine experiment uses this helper
    to prevent an unchecked tail candidate from entering the matching set.
    """
    if poly is None:
        raise ValueError("cannot validate ADtrans candidates without a polynomial")

    inconsistent = []
    for dealer in key_proposal:
        actual = shares_list[dealer]
        actual_value = actual.value if hasattr(actual, "value") else int(actual)
        expected = poly(point(dealer))
        expected_value = (
            expected.value if hasattr(expected, "value") else int(expected)
        )
        if actual_value != expected_value:
            inconsistent.append(int(dealer))
    return inconsistent


async def robust_reconstruct(field_futures, field, n, t, point, degree):
    use_omega_powers = point.use_omega_powers
    enc = EncoderFactory.get(
        point, Algorithm.FFT if use_omega_powers else Algorithm.VANDERMONDE
    )
    dec = DecoderFactory.get(
        point, Algorithm.FFT if use_omega_powers else Algorithm.VANDERMONDE
    )
    robust_dec = RobustDecoderFactory.get(t, point, algorithm=Algorithm.GAO)
    incremental_decoder = IncrementalDecoder(enc, dec, robust_dec, degree, 1, t)

    async for (idx, d) in fetch_one(field_futures):
        print(f"idx: {idx}, d.value: {d.value}")
        print(f"type idx: {type(idx)}")
        print(f"type d.value: {type(d.value)}")
        incremental_decoder.add(idx, [d.value])
        
        if incremental_decoder.done():
            polys, errors = incremental_decoder.get_results()
            return polynomials_over(field)(polys[0]), errors
    return None, None

async def robust_reconstruct_admpc(shares_list, key_proposal, field, t, point, degree):


    use_omega_powers = point.use_omega_powers
    enc = EncoderFactory.get(
        point, Algorithm.FFT if use_omega_powers else Algorithm.VANDERMONDE
    )
    dec = DecoderFactory.get(
        point, Algorithm.FFT if use_omega_powers else Algorithm.VANDERMONDE
    )
    robust_dec = RobustDecoderFactory.get(t, point, algorithm=Algorithm.GAO)
    incremental_decoder = IncrementalDecoder(enc, dec, robust_dec, degree, 1, t)

    for i in range(len(shares_list)):
        if i in key_proposal: 
            val = shares_list[i]
            val = val.value if hasattr(val, "value") else int(val)
            incremental_decoder.add(i, [val])


        if incremental_decoder.done(): 
            polys, errors = incremental_decoder.get_results()
            return polynomials_over(field)(polys[0]), errors
    
    return None, None

async def robust_rec_admpc(shares_list, key_proposal, field, t, point, degree):
    use_omega_powers = point.use_omega_powers
    enc = EncoderFactory.get(
        point, Algorithm.FFT if use_omega_powers else Algorithm.VANDERMONDE
    )
    dec = DecoderFactory.get(
        point, Algorithm.FFT if use_omega_powers else Algorithm.VANDERMONDE
    )
    robust_dec = RobustDecoderFactory.get(t, point, algorithm=Algorithm.GAO)
    
    
    incremental_decoder = IncrementalDecoder(enc, dec, robust_dec, degree, 1, t)



    for i in range(len(shares_list)):
        # if i == 2: i = i + 1
        val = shares_list[i]
        val = val.value if hasattr(val, "value") else int(val)
        incremental_decoder.add(key_proposal[i], [val])


        if incremental_decoder.done():
            # print(f"incremental_decoder.done()")
            polys, errors = incremental_decoder.get_results()
            return polynomials_over(field)(polys[0]), errors
    
    return None, None
