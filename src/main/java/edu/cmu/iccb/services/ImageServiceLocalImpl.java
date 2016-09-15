package edu.cmu.iccb.services;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

import javax.imageio.ImageIO;

import java.nio.file.Path;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;

//@Service
public class ImageServiceLocalImpl implements ImageService {

    
    private String rootDir;
      
    @Autowired
    public ImageServiceLocalImpl(@Value("${uploadDir}") String root) {
    	this.rootDir = root;
    	
		Path rootPath = Paths.get(rootDir);
		File rootFile = rootPath.toFile();
		
		if (!rootFile.exists()) {
			rootFile.mkdirs();
		}
    }

    @Override
    public byte[] getImageData(String id) throws IOException {
        Path path = Paths.get(rootDir + "/"+id);
        byte[] image = Files.readAllBytes(path);
        return image;
    }
    
	@Override
	public void saveImage(String imageName, InputStream inputStream) throws IOException {
		
		BufferedImage inputImage = ImageIO.read(inputStream);
		long imageId = System.currentTimeMillis();
		
		Path outputPath = Paths.get(rootDir, Long.toString(imageId));		

		ImageIO.write(inputImage, "png", outputPath.toFile());		
	}

	@Override
	public byte[] getThumbnailData(String id) throws IOException {
		return getImageData(id);
	}

	@Override
	public List<String> getUploadedImages() {
        
		File rootFolder = new File(rootDir);
		
        List<String> fileNames = Arrays.stream(rootFolder.listFiles())
        	.sorted(Comparator.comparingLong(f -> -1 * f.lastModified()))
            .map(f -> f.getName())
            .collect(Collectors.toList());        
        
        return fileNames;
	}
}
