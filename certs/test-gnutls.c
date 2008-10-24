#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/pkcs12.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main (int argc, char **argv)
{
	gnutls_x509_privkey_t pk1, pk2, pk3, pk4, pk_orig;
	gnutls_datum_t datum[4];
        int error;
        int i;

        gnutls_global_init ();

        gnutls_x509_privkey_init (&pk1);
        gnutls_x509_privkey_init (&pk2);
        gnutls_x509_privkey_init (&pk3);
        gnutls_x509_privkey_init (&pk4);
        gnutls_x509_privkey_init (&pk_orig);

        printf ("Generating RSA certificate...\n", argv[1]);
        if (gnutls_x509_privkey_generate (pk_orig, GNUTLS_PK_RSA, 1024, 0) < 0) {
                fprintf(stderr, "Error while creating private key.\n");
                return 1;
        }

        datum[0].size = 0;
        datum[0].data = NULL;
        datum[1].size = 0;
        datum[1].data = NULL;
        datum[2].size = 0;
        datum[2].data = NULL;
        datum[3].size = 0;
        datum[3].data = NULL;

        gnutls_x509_privkey_export_pkcs8 (pk_orig, GNUTLS_X509_FMT_PEM, "foobar", GNUTLS_PKCS_USE_PKCS12_3DES, datum[0].data, &(datum[0].size));
        datum[0].data = calloc (datum[0].size, sizeof (unsigned char));

        error = gnutls_x509_privkey_export_pkcs8 (pk_orig, GNUTLS_X509_FMT_PEM, "foobar", GNUTLS_PKCS_USE_PKCS12_3DES, datum[0].data, &datum[0].size);
        if (error != GNUTLS_E_SUCCESS) {
                fprintf(stderr, "Error while exporting private key: %d\n", error);
                return 2;
        }

        gnutls_x509_privkey_export_pkcs8 (pk_orig, GNUTLS_X509_FMT_PEM, NULL, 0, datum[1].data, &(datum[1].size));
        datum[1].data = calloc (datum[1].size, sizeof (unsigned char));

        error = gnutls_x509_privkey_export_pkcs8 (pk_orig, GNUTLS_X509_FMT_PEM, NULL, 0, datum[1].data, &datum[1].size);
        if (error != GNUTLS_E_SUCCESS) {
                fprintf(stderr, "Error while exporting private key: %d\n", error);
                return 3;
        }

        gnutls_x509_privkey_export_pkcs8 (pk_orig, GNUTLS_X509_FMT_DER, "foobar", GNUTLS_PKCS_USE_PKCS12_3DES, datum[2].data, &(datum[2].size));
        datum[2].data = calloc (datum[2].size, sizeof (unsigned char));

        error = gnutls_x509_privkey_export_pkcs8 (pk_orig, GNUTLS_X509_FMT_DER, "foobar", GNUTLS_PKCS_USE_PKCS12_3DES, datum[2].data, &datum[2].size);
        if (error != GNUTLS_E_SUCCESS) {
                fprintf(stderr, "Error while exporting private key: %d\n", error);
                return 4;
        }

        gnutls_x509_privkey_export_pkcs8 (pk_orig, GNUTLS_X509_FMT_DER, NULL, 0, datum[3].data, &(datum[3].size));
        datum[3].data = calloc (datum[3].size, sizeof (unsigned char));

        error = gnutls_x509_privkey_export_pkcs8 (pk_orig, GNUTLS_X509_FMT_DER, NULL, 0, datum[3].data, &datum[3].size);
        if (error != GNUTLS_E_SUCCESS) {
                fprintf(stderr, "Error while exporting private key: %d\n", error);
                return 5;
        }

        for (i=0; i<4; i++) {
                printf ("\n\nCert #%d\n", i);
                printf ("Importing as crypted PEM: %d\n", 
                        gnutls_x509_privkey_import_pkcs8 (pk2, &datum[i], GNUTLS_X509_FMT_PEM, "foobar", 0));
                printf ("Importing as unencrypted PEM: %d\n", 
                        gnutls_x509_privkey_import_pkcs8 (pk1, &datum[i], GNUTLS_X509_FMT_PEM, NULL, 0));
                printf ("Importing as crypted DER: %d\n", 
                        gnutls_x509_privkey_import_pkcs8 (pk4, &datum[i], GNUTLS_X509_FMT_DER, "foobar", 0));
                printf ("Importing as unencrypted DER: %d\n", 
                        gnutls_x509_privkey_import_pkcs8 (pk3, &datum[i], GNUTLS_X509_FMT_DER, NULL, GNUTLS_PKCS_PLAIN));
        }
        gnutls_x509_privkey_deinit (pk1);
        gnutls_x509_privkey_deinit (pk2);
        gnutls_x509_privkey_deinit (pk3);
        gnutls_x509_privkey_deinit (pk4);

}
