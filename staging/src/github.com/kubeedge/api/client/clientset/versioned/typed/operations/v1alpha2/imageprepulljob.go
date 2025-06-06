/*
Copyright The KubeEdge Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by client-gen. DO NOT EDIT.

package v1alpha2

import (
	"context"
	"time"

	v1alpha2 "github.com/kubeedge/api/apis/operations/v1alpha2"
	scheme "github.com/kubeedge/api/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// ImagePrePullJobsGetter has a method to return a ImagePrePullJobInterface.
// A group's client should implement this interface.
type ImagePrePullJobsGetter interface {
	ImagePrePullJobs() ImagePrePullJobInterface
}

// ImagePrePullJobInterface has methods to work with ImagePrePullJob resources.
type ImagePrePullJobInterface interface {
	Create(ctx context.Context, imagePrePullJob *v1alpha2.ImagePrePullJob, opts v1.CreateOptions) (*v1alpha2.ImagePrePullJob, error)
	Update(ctx context.Context, imagePrePullJob *v1alpha2.ImagePrePullJob, opts v1.UpdateOptions) (*v1alpha2.ImagePrePullJob, error)
	UpdateStatus(ctx context.Context, imagePrePullJob *v1alpha2.ImagePrePullJob, opts v1.UpdateOptions) (*v1alpha2.ImagePrePullJob, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha2.ImagePrePullJob, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha2.ImagePrePullJobList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha2.ImagePrePullJob, err error)
	ImagePrePullJobExpansion
}

// imagePrePullJobs implements ImagePrePullJobInterface
type imagePrePullJobs struct {
	client rest.Interface
}

// newImagePrePullJobs returns a ImagePrePullJobs
func newImagePrePullJobs(c *OperationsV1alpha2Client) *imagePrePullJobs {
	return &imagePrePullJobs{
		client: c.RESTClient(),
	}
}

// Get takes name of the imagePrePullJob, and returns the corresponding imagePrePullJob object, and an error if there is any.
func (c *imagePrePullJobs) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha2.ImagePrePullJob, err error) {
	result = &v1alpha2.ImagePrePullJob{}
	err = c.client.Get().
		Resource("imageprepulljobs").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of ImagePrePullJobs that match those selectors.
func (c *imagePrePullJobs) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha2.ImagePrePullJobList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha2.ImagePrePullJobList{}
	err = c.client.Get().
		Resource("imageprepulljobs").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested imagePrePullJobs.
func (c *imagePrePullJobs) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Resource("imageprepulljobs").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a imagePrePullJob and creates it.  Returns the server's representation of the imagePrePullJob, and an error, if there is any.
func (c *imagePrePullJobs) Create(ctx context.Context, imagePrePullJob *v1alpha2.ImagePrePullJob, opts v1.CreateOptions) (result *v1alpha2.ImagePrePullJob, err error) {
	result = &v1alpha2.ImagePrePullJob{}
	err = c.client.Post().
		Resource("imageprepulljobs").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(imagePrePullJob).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a imagePrePullJob and updates it. Returns the server's representation of the imagePrePullJob, and an error, if there is any.
func (c *imagePrePullJobs) Update(ctx context.Context, imagePrePullJob *v1alpha2.ImagePrePullJob, opts v1.UpdateOptions) (result *v1alpha2.ImagePrePullJob, err error) {
	result = &v1alpha2.ImagePrePullJob{}
	err = c.client.Put().
		Resource("imageprepulljobs").
		Name(imagePrePullJob.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(imagePrePullJob).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *imagePrePullJobs) UpdateStatus(ctx context.Context, imagePrePullJob *v1alpha2.ImagePrePullJob, opts v1.UpdateOptions) (result *v1alpha2.ImagePrePullJob, err error) {
	result = &v1alpha2.ImagePrePullJob{}
	err = c.client.Put().
		Resource("imageprepulljobs").
		Name(imagePrePullJob.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(imagePrePullJob).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the imagePrePullJob and deletes it. Returns an error if one occurs.
func (c *imagePrePullJobs) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Resource("imageprepulljobs").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *imagePrePullJobs) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Resource("imageprepulljobs").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched imagePrePullJob.
func (c *imagePrePullJobs) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha2.ImagePrePullJob, err error) {
	result = &v1alpha2.ImagePrePullJob{}
	err = c.client.Patch(pt).
		Resource("imageprepulljobs").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
