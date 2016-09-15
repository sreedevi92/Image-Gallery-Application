package edu.cmu.iccb.services;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

public interface ImageService {

    public byte[] getImageData(String name) throws IOException;

	public void saveImage(String imageName, InputStream inputStream) throws IOException;

	public byte[] getThumbnailData(String id) throws IOException;

	public List<String> getUploadedImages();
}
