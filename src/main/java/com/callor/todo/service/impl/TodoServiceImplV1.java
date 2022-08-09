package com.callor.todo.service.impl;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.callor.todo.model.TodoVO;
import com.callor.todo.persistance.TodoDao;
import com.callor.todo.service.TodoService;

@Service
public class TodoServiceImplV1 implements TodoService{
	
	@Autowired
	private TodoDao todoDao;

	@Override
	public List<TodoVO> findByUsername(String username) {
		return todoDao.findByUsername(username);
	}

	@Override
	public List<TodoVO> selectAll() {
		return todoDao.selectAll();
	}

	@Override
	public TodoVO findById(Long id) {
		return todoDao.findById(id);
	}

	@Override
	public int insert(TodoVO vo) {
		
		Date date = new Date(System.currentTimeMillis());
		 
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
		SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:SS");
		 
		vo.setT_sdate(dateFormat.format(date));
		vo.setT_stime(timeFormat.format(date));
		return todoDao.insert(vo);
	}

	@Override
	public int update(TodoVO vo) {
		
		Date date = new Date(System.currentTimeMillis());
		 
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
		SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:SS");
		 
		vo.setT_edate(dateFormat.format(date));
		vo.setT_etime(timeFormat.format(date));
		return todoDao.update(vo);
	}

	@Override
	public int delete(Long id) {
		return 0;
	}

}
