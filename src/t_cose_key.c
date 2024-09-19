/*
 * t_cose_key.c
 *
 * Copyright 2023, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * Created by Laurence Lundblade on 2/6/23.
 *
 * See BSD-3-Clause license in README.md
 */
#include "qcbor/qcbor_encode.h"
#include "t_cose/t_cose_key.h"
#include "t_cose_crypto.h"
#include "t_cose_crypto.h"
#include "t_cose_util.h"


/*
 * Public function. See t_cose_key.h
 */
enum t_cose_err_t
t_cose_key_init_symmetric(int32_t                cose_algorithm_id,
                          struct q_useful_buf_c  symmetric_key,
                          struct t_cose_key     *key)
{
    return  t_cose_crypto_make_symmetric_key_handle(cose_algorithm_id,
                                                    symmetric_key,
                                                    key);
}


/*
 * Public function. See t_cose_key.h
 */
void
t_cose_key_free_symmetric(struct t_cose_key key)
{
    t_cose_crypto_free_symmetric_key(key);
}

/*
 * Public function. See t_cose_key.h
 */
enum t_cose_err_t
t_cose_key_encode(struct t_cose_key      key,
                  struct q_useful_buf    key_buf,
                  struct q_useful_buf_c *cbor_encoded)
{
    enum t_cose_err_t      result;
    int32_t                cose_curve;
    MakeUsefulBufOnStack(  x_coord_buf, T_COSE_BITS_TO_BYTES(T_COSE_ECC_MAX_CURVE_BITS));
    MakeUsefulBufOnStack(  y_coord_buf, T_COSE_BITS_TO_BYTES(T_COSE_ECC_MAX_CURVE_BITS));
    struct q_useful_buf_c  x_coord;
    struct q_useful_buf_c  y_coord;
    bool                   y_sign;
    QCBOREncodeContext     cbor_encoder;
    QCBORError             qcbor_result;

    result = t_cose_crypto_export_ec2_key(key,
                                          &cose_curve,
                                          x_coord_buf,
                                          &x_coord,
                                          y_coord_buf,
                                          &y_coord,
                                          &y_sign);
    if (result != T_COSE_SUCCESS) {
        return result;
    }

    QCBOREncode_Init(&cbor_encoder, key_buf);

    QCBOREncode_OpenMap(&cbor_encoder);

    QCBOREncode_AddInt64ToMapN(&cbor_encoder, T_COSE_KEY_COMMON_KTY, T_COSE_KEY_TYPE_EC2);
    QCBOREncode_AddInt64ToMapN(&cbor_encoder, T_COSE_KEY_PARAM_CRV, cose_curve);
    QCBOREncode_AddBytesToMapN(&cbor_encoder, T_COSE_KEY_PARAM_X_COORDINATE, x_coord);
    if (q_useful_buf_c_is_null(y_coord)) {
        QCBOREncode_AddBoolToMapN(&cbor_encoder, T_COSE_KEY_PARAM_Y_COORDINATE, y_sign);
    } else {
        QCBOREncode_AddBytesToMapN(&cbor_encoder, T_COSE_KEY_PARAM_Y_COORDINATE, y_coord);
    }

    QCBOREncode_CloseMap(&cbor_encoder);

    qcbor_result = QCBOREncode_Finish(&cbor_encoder, cbor_encoded);
    if (qcbor_result != QCBOR_SUCCESS) {
        /* Mainly means that the COSE_Key was too big for key_buf */
        return qcbor_encode_error_to_t_cose_error(&cbor_encoder);
    }

    return T_COSE_SUCCESS;
}
