/*
 * Copyright (c) 2007 Universitat Politecnica de Catalunya
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id$
 */

#include <math.h>
#include "como.h"
#include "comotypes.h"
#include "comopriv.h"


/*
 * -- new_vector
 *  
 *  allocate memory for a vector of double precision
 *  floating point numbers with n positions
 *
 */
double *
new_vector(int n)
{
    double *vector;

    /* allocate space for the vector */
    vector = (double *)como_calloc(1, n * sizeof(double));
    
    return vector;
}


/*
 * -- delete_vector
 *
 *  free the memory occupied by a vector allocated using new_vector()
 *
 */
void
delete_vector(double *vector)
{
    free(vector);
}


/*
 * -- new_matrix
 *  
 *  allocate memory for a (N rows * M columns) matrix of double precision
 *  floating point numbers
 *
 */
double **
new_matrix(int n, int m)
{
    int i;
    double **matrix;

    /* allocate pointers to rows */
    matrix = (double **)como_calloc(1, n * sizeof(double *));
    
    /* allocate rows and set pointers to them */
    matrix[0] = (double *)como_calloc(1, n * m * sizeof(double));
    for(i = 1; i < n; i++)
        matrix[i] = matrix[i - 1] + m;

    /* return pointer to array of pointers to rows */
    return matrix;
}


/*
 * -- delete_matrix
 *  
 *  free the memory occupied by a matrix allocated using new_matrix()
 *
 */
void
delete_matrix(double **matrix)
{
    free(matrix[0]);
    free(matrix);
}


/*
 * corrcoef() - Calculates the linear correlation coefficient between two
 *              variables.
 * 
 * -- input --
 * x: vector with values of the x variable
 * y: vector with values of the y variable
 * nobs: number of values
 * 
 * -- output --
 * r: linear correlation coefficient
 * 
 */
static double
corrcoef(double *x, double *y, int nobs)
{
    double sum_sq_x = 0, sum_sq_y = 0, sum_coproduct = 0;
    double mean_x, mean_y;
    double sweep;
    double delta_x, delta_y;
    double pop_sd_x, pop_sd_y, cov_x_y;
    int i;
    
    mean_x = x[0];
    mean_y = y[0];
    
    for (i = 2; i <= nobs; i++) {
        sweep = (i - 1.0) / i;
        delta_x = x[i - 1] - mean_x;
        delta_y = y[i - 1] - mean_y;
        sum_sq_x += delta_x * delta_x * sweep;
        sum_sq_y += delta_y * delta_y * sweep;
        sum_coproduct += delta_x * delta_y * sweep;
        mean_x += delta_x / i;
        mean_y += delta_y / i;
    }
    
    pop_sd_x = sqrtf(sum_sq_x / nobs);
    pop_sd_y = sqrtf(sum_sq_y / nobs);
    cov_x_y = sum_coproduct / nobs;

    return (cov_x_y / (pop_sd_x * pop_sd_y));
}


/*
 * pred_sel() - Fast Correlation Based Filter for predictor selection
 * 
 */
void
pred_sel(mdl_ls_t *mdl_ls)
{
    int i, j, k;
    prediction_t *pred;
    double redund;

    pred = &mdl_ls->pred;

    pred->nsel = 0;

    for (i = 0; i < NUM_PREDS; i++) {
        /* Empty the selected predictors array */
        pred->sel[i] = NULL;

        /* Calculate the correlation coefficient for the predictor */
        pred->hist[i].corrcoef =
            corrcoef(pred->hist[i].values, pred->resp, NUM_OBS);
    }
    
    /* Create a list of predictors highly correlated with the value,
     * ordered by their correlation coefficient */
    for (i = 0; i < NUM_PREDS; i++) {
        if (fabs(pred->hist[i].corrcoef) > CORR_THRESH) {
            for (j = 0; pred->sel[j] && fabs(pred->hist[i].corrcoef) <
                    fabs(pred->sel[j]->corrcoef); j++);
            if (pred->sel[j])
                for (k = NUM_PREDS - 1; k > j; k--)
                    pred->sel[k] = pred->sel[k - 1];
            pred->sel[j] = &(pred->hist[i]);
        }
    }
    
    /* Delete the redundant predictors from the list */
    for (i = 0; i < NUM_PREDS; i++) {
        if (!pred->sel[i])
            continue;
        pred->nsel++;
        for (j = i + 1; j < NUM_PREDS; j++) {
            if (!pred->sel[j])
                continue;
            redund = corrcoef(pred->sel[i]->values,
                              pred->sel[j]->values, NUM_OBS);
            if (fabs(redund) > fabs(pred->sel[j]->corrcoef))
                pred->sel[j] = NULL;
        }
    }
}


/*
 * pythag() - Computes (a2 + b2)1/2 without destructive underflow or overflow.
 */
#define SQR(a) (a == 0.0 ? 0.0 : a*a)
double pythag(double a, double b)
{
    double absa, absb;
    absa = fabs(a);
    absb = fabs(b);
    if (absa > absb) return absa * sqrt(1.0 + SQR(absb/absa));
    else return (absb == 0.0 ? 0.0 : absb * sqrt(1.0 + SQR(absa/absb)));
}


/*
 * -- svd
 *
 * Singular Value Decomposition algorithm - Adapted and translated from
 * the "svd" fortran subroutine of the EISPACK library (www.netlib.org)
 *
 * -- input
 *  u: rectangular input matrix to be decomposed
 *  m: number of rows of a (and u)
 *  n: number of columns of a (and u) and the order of v
 *
 * -- output
 *  w: contains the n (non-negative) singular values of a (the diagonal
 *     elements of s). They are unordered. In case of error, the singular
 *     values should be correct for indices ierr+1, ierr+2, ..., n
 *  u: matrix (orthogonal column vectors) of the decomposition.
 *     In case of error, the columns of u corresponding to indices of correct
 *     singular values should be correct
 *  v: matrix (orthogonal) of the decomposition.
 *     In case of error, the columns of v corresponding to indices of correct
 *     singular values should be correct
 *
 * the return value is set to:
 *  zero    for normal return,
 *  k       if the k-th singular value has not been determined after 30
 *          iterations
 *
 */
#define sign(a,b)   ((b >= 0.0)? fabs(a) : -fabs(a))
#define max(a,b)    ((a >= b)? a : b)
#define min(a,b)    ((a >= b)? b : a)
/* Need to declare the EPSILON constant because precision issues
 * may cause the algorithm to not converge when diagonalizing the matrix.
 */
#define EPSILON 4.94065645841247e-324
static int
svd(int m, int n, double *w, double **u, double **v)
{
    int i, i1, j, l, l1, k, k1, its;
    double g, scale, x, y, z, s, f, h, tst1, tst2, c;
    double rv1[n];

    /* householder reduction to bidiagonal form */
    g = 0.0;
    scale = 0.0;
    x = 0.0;

    for (i = 0; i < n; i++) {
        l = i + 1;
        rv1[i] = scale * g;
        g = 0.0;
        s = 0.0;
        scale = 0.0;
        
        if (i > (m - 1)) goto lbl210;
        
        for (k = i; k < m; k++)
            scale += fabs(u[k][i]);
        
        if (scale == 0.0) goto lbl210;

        for (k = i; k < m; k++) {
            u[k][i] /= scale;
            s += u[k][i] * u[k][i];
        }

        f = u[i][i];
        g = -sign(sqrt(s), f);
        h = f * g - s;
        u[i][i] = f - g;
        
        if (i == (n - 1)) goto lbl190;

        for (j = l; j < n; j++) {
            s = 0.0;
            
            for (k = i; k < m; k++)
                s += u[k][i] * u[k][j];

            f = s / h;

            for (k = i; k < m; k++)
                u[k][j] += f * u[k][i];
        }

lbl190:
        for (k = i; k < m; k++)
            u[k][i] *= scale;
        
lbl210:
        w[i] = scale * g;
        g = 0.0;
        s = 0.0;
        scale = 0.0;

        if (i > (m - 1) || i == (n - 1)) goto lbl290;

        for (k = l; k < n; k++)
            scale += fabs(u[i][k]);

        if (scale == 0.0) goto lbl290;
        
        for (k = l; k < n; k++) {
            u[i][k] /= scale;
            s += u[i][k] * u[i][k];
        }
        
        f = u[i][l];
        g = -sign(sqrt(s), f);
        h = f * g - s;
        u[i][l] = f - g;

        for (k = l; k < n; k++)
            rv1[k] = u[i][k] / h;

        if (i == (m - 1)) goto lbl270;

        for (j = l; j < m; j++) {
            s = 0.0;

            for (k = l; k < n; k++)
                s += u[j][k] * u[i][k];

            for (k = l; k < n; k++)
                u[j][k] += s * rv1[k];
        }

lbl270:
        for (k = l; k < n; k++)
            u[i][k] *= scale;

lbl290:
        x = max(x, fabs(w[i]) + fabs(rv1[i]));
    }

    /* accumulation of right-hand transformations */
    for (i = n - 1; i >= 0; i--) {
        if (i == (n - 1)) goto lbl390;

        if (g == 0.0) goto lbl360;
        
        for (j = l; j < n; j++)
            /* double division avoids possible underflow */
            v[j][i] = (u[i][j] / u[i][l]) / g;

        for (j = l; j < n; j++) {
            s = 0.0;

            for (k = l; k < n; k++)
                s += u[i][k] * v[k][j];
            
            for (k = l; k < n; k++)
                v[k][j] += s * v[k][i];
        }

lbl360:
        for (j = l; j < n; j++) {
            v[i][j] = 0.0;
            v[j][i] = 0.0;
        }

lbl390:
        v[i][i] = 1.0;
        g = rv1[i];
        l = i;
    }

    /* accumulation of left-hand transformations */
    for (i = min(m,n) - 1; i >= 0; i--) {
        l = i + 1;
        g = w[i];
        if (i == (n - 1)) goto lbl430;

        for (j = l; j < n; j++)
            u[i][j] = 0.0;
            
lbl430:
        if (g == 0.0) goto lbl475;

        if (i == (min(m,n) - 1)) goto lbl460;

        for (j = l; j < n; j++) {
            s = 0.0;
            for (k = l; k < m; k++)
                s += u[k][i] * u[k][j];
            
            /* double division avoids possible underflow */
            f = (s / u[i][i]) / g;

            for (k = i; k < m; k++)
                u[k][j] += f * u[k][i];
        }

lbl460:
        for (j = i; j < m; j++)
            u[j][i] /= g;

        goto lbl490;

lbl475:
        for (j = i; j < m; j++)
            u[j][i] = 0.0;

lbl490:
        u[i][i] += 1.0;
    }

    /* diagonalization of the bidiagonal form */
    tst1 = x;

    for (k = n - 1; k >= 0; k--) {
        k1 = k - 1;
        its = 0;

lbl520:
        /* test for splitting */
        for (l = k; l >= 0; l--) {
            l1 = l - 1;
            tst2 = tst1 + fabs(rv1[l]);
            if (fabs(tst2 - tst1) <= EPSILON) goto lbl565;
            /* rv1[0] is always 0, so there is
             * no exit through the bottom of the loop */
            tst2 = tst1 + fabs(w[l1]);
            if (fabs(tst2 - tst1) <= EPSILON) goto lbl540;
        }

lbl540:
        /* cancellation of rv1[l] if l greater than 0 */
        c = 0.0;
        s = 1.0;        

        for (i = l; i <= k; i++) {
            f = s * rv1[i];
            rv1[i] *= c;
            tst2 = tst1 + fabs(f);
            if (fabs(tst2 - tst1) <= EPSILON) goto lbl565;
            g = w[i];
            h = pythag(f, g);
            w[i] = h;
            c = g / h;
            s = -f / h;

            for (j = 0; j < m; j++) {
                y = u[j][l1];
                z = u[j][i];
                u[j][l1] = y * c + z * s;
                u[j][i] = -y * s + z * c;
            }
        }

lbl565:
        /* test for convergence */
        z = w[k];
        if (l == k) goto lbl650;

        /* shift from bottom 2 by 2 minor */
        if (its == 30)
            return k;

        its++;
        x = w[l];
        y = w[k1];
        g = rv1[k1];
        h = rv1[k];
        f = 0.5 * (((g + z) / h) * ((g - z) / y) + y / h - h / y);
        g = pythag(f, 1.0);
        f = x - (z / x) * z + (h / x) * (y / (f + sign(g, f)) - h);
        
        /* next qr transformation */
        c = 1.0;
        s = 1.0;
        
        for (i1 = l; i1 <= k1; i1++) {
            i = i1 + 1;
            g = rv1[i];
            y = w[i];
            h = s * g;
            g = c * g;
            z = pythag(f, h);
            rv1[i1] = z;
            c = f / z;
            s = h / z;
            f = x * c + g * s;
            g = -x * s + g * c;
            h = y * s;
            y = y * c;

            for (j = 0; j < n; j++) {
                x = v[j][i1];
                z = v[j][i];
                v[j][i1] = x * c + z * s;
                v[j][i] = -x * s + z * c;
            }

            z = pythag(f, h);
            w[i1] = z;
            
            /* rotation can be arbitrary if z is zero */
            if (z == 0.0) goto lbl580;
            c = f / z;
            s = h / z;
lbl580:
            f = c * g + s * y;
            x = -s * g + c * y;

            for (j = 0; j < m; j++) {
                y = u[j][i1];
                z = u[j][i];
                u[j][i1] = y * c + z * s;
                u[j][i] = -y * s + z * c;
            }
        }

        rv1[l] = 0.0;
        rv1[k] = f;
        w[k] = x;
        goto lbl520;

lbl650:
        /* convergence */
        /* w[k] is made non-negative */
        if (z < 0.0) {
            w[k] = -z;
            for (j = 0; j < n; j++)
                v[j][k] = -v[j][k];
        }

    }
    
    return 0;
}


/*
 * -- mlr
 *
 * Multiple Linear Regression algorithm, using Singular Value Decomposition
 * to find the solution of the linear equations.
 *
 * -- input
 *  u: matrix with a copy of the selected predictors
 *  y: vector with the values of the response variable
 *  nsel: number of selected predictors
 *  nobs: number of observations
 *
 * -- input/output
 *  c: coefficients of the fitting function
 *  
 */
static void
mlr(double **u, double *y, int nsel, int nobs, double *c)
{
    int i, j, jj, error;
    double s;

    double *w = new_vector(nsel);
    double **v = new_matrix(nsel, nsel);
    double *tmp = new_vector(nsel);

    /* Decompose the u matrix using SVD */
    error = svd(nobs, nsel, w, u, v);
    if (error)
        warn("SVD algorithm failed on the %d-th singular value\n", error);
    
    /* XXX Edit the singular values, given a constant tolerance! */

    /* Calculate the coefficients */
    for (j = 0; j < nsel; j++) {
        s = 0.0;
        if (w[j]) {
            for (i = 0; i < nobs; i++)
                s += u[i][j] * y[i];
            s /= w[j];
        }
        tmp[j] = s;
    }

    /* multiply by the matrix v to get the answer */
    for (j = 0; j < nsel; j++) {
        s = 0.0; 
        for (jj = 0; jj < nsel; jj++)
            s += v[j][jj] * tmp[jj];
        c[j] = s;
    }

    /* Cleanup */
    delete_vector(w);
    delete_matrix(v);
    delete_vector(tmp);
}


/*
 * -- update_pred_hist
 *
 * Update the predictor history of a module using values from the
 * calculated features
 *
 */
void
update_pred_hist(mdl_ls_t *mdl_ls)
{
    int i;
    prediction_t *pred = &mdl_ls->pred;

    for (i = 0; i < NUM_PREDS; i++)
        pred->hist[i].values[mdl_ls->obs] = mdl_ls->fextr.feats[i].value;
}


/*
 * -- predict
 *
 * Construct a predictor matrix with the history of selected predictors
 * and call the MLR algorithm
 *
 */
double
predict(mdl_ls_t *mdl_ls)
{
    int i, ii, j, jj;
    prediction_t *pred;
    double **m = new_matrix(NUM_OBS, NUM_PREDS + 1);
    double *c = new_vector(NUM_PREDS + 1);
    double pr;

    pred = &mdl_ls->pred;

    /* Copy predictor history */
    for (i = 0; i < NUM_OBS; i++) {
        m[i][0] = 1;  /* constant term */
        for (j = 0, jj = 0; j < NUM_PREDS; j++)
            if (pred->sel[j]) {
                m[i][jj + 1] = pred->sel[j]->values[i];
                jj++;
            }
    }

    /* Initialize coefficients vector */
    for (i = 0; i < NUM_PREDS + 1; i++)
        c[i] = 0;

    /* Multiple Linear Regression */
    mlr(m, pred->resp, pred->nsel + 1, NUM_OBS, c);

    /* Add new features to the predictor history */
    update_pred_hist(mdl_ls);

    /* Calculate the prediction */
    pr = c[0];
    for (i = 0, ii = 1; i < NUM_PREDS; i++) {
        if (pred->sel[i]) {
            pr += pred->sel[i]->values[mdl_ls->obs] * c[ii];
            ii++;
        }
    }
    
    if (pr < 0)
        pr = 0;

    /* Cleanup */
    delete_matrix(m);
    delete_vector(c);

    return pr;
}
